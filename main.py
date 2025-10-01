import os
import struct
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import zlib
import sys
from typing import List, Dict, Tuple, Optional, BinaryIO

# 常量定义
MAGIC_NUMBER = b'MUARDO'
VERSION = 1
HEADER_SIZE = 16  # 魔数(6) + 版本(2) + 索引大小(4) + 哈希区大小(4)
INDEX_ENTRY_SIZE = 4 + 4 + 256  # 开始位置(4) + 结束位置(4) + 路径(256)
HASH_SIZE = 8  # 每个文件的哈希值大小
BLOCK_SIZE = AES.block_size

class MuardoPackager:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
    
    def log(self, message: str):
        """记录日志信息"""
        if not self.quiet:
            print(message)
    
    def calculate_hash(self, data: bytes) -> bytes:
        """计算8位哈希值"""
        return hashlib.sha256(data).digest()[:HASH_SIZE]
    
    def encrypt_data(self, data: bytes, key: str) -> bytes:
        """使用AES加密数据"""
        aes_key = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data, BLOCK_SIZE))
        return cipher.iv + ct_bytes
    
    def decrypt_data(self, data: bytes, key: str) -> bytes:
        """使用AES解密数据"""
        aes_key = hashlib.sha256(key.encode()).digest()
        iv = data[:BLOCK_SIZE]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(data[BLOCK_SIZE:]), BLOCK_SIZE)
    
    def compress_data(self, data: bytes) -> bytes:
        """使用LZ77压缩数据"""
        return zlib.compress(data)
    
    def decompress_data(self, data: bytes) -> bytes:
        """解压LZ77压缩的数据"""
        return zlib.decompress(data)
    
    def build_index(self, file_entries: List[Dict]) -> Tuple[bytes, Dict]:
        """构建索引区"""
        index_data = b''
        hash_data = b''
        index_info = {}
        
        for entry in file_entries:
            # 索引条目: 开始位置(4), 结束位置(4), 路径(256)
            path_bytes = entry['path'].encode('utf-8')[:255]
            path_padded = path_bytes.ljust(256, b'\x00')
            index_entry = struct.pack('<II', entry['start'], entry['end']) + path_padded
            index_data += index_entry
            
            # 哈希条目
            hash_data += entry['hash']
            
            # 存储索引信息
            index_info[entry['path']] = {
                'start': entry['start'],
                'end': entry['end'],
                'hash': entry['hash']
            }
        
        return index_data, hash_data, index_info
    
    def pack_files(self, input_paths: List[str], output_file: str, 
                  encryption_key: Optional[str] = None, 
                  compress: bool = False,
                  progress_callback: Optional[callable] = None) -> bool:
        """打包文件为.muardo格式"""
        try:
            file_entries = []
            current_position = HEADER_SIZE
            
            # 第一阶段: 收集文件和计算哈希
            self.log("正在收集文件信息...")
            all_files = []
            for path in input_paths:
                if os.path.isfile(path):
                    all_files.append((path, path))
                else:
                    for root, _, files in os.walk(path):
                        for file in files:
                            full_path = os.path.join(root, file)
                            rel_path = os.path.relpath(full_path, os.path.dirname(path))
                            all_files.append((full_path, rel_path))
            
            total_size = sum(os.path.getsize(f[0]) for f in all_files)
            processed_size = 0
            
            # 第二阶段: 构建索引和哈希
            for i, (full_path, rel_path) in enumerate(all_files):
                with open(full_path, 'rb') as f:
                    file_data = f.read()
                
                file_hash = self.calculate_hash(file_data)
                file_size = len(file_data)
                
                file_entries.append({
                    'path': rel_path,
                    'start': current_position,
                    'end': current_position + file_size,
                    'hash': file_hash,
                    'data': file_data
                })
                
                current_position += file_size
                processed_size += file_size
                
                if progress_callback:
                    progress_callback(
                        overall=processed_size / total_size,
                        file=(i + 1) / len(all_files),
                        current_file=rel_path
                    )
            
            # 构建索引区和哈希区
            index_data, hash_data, _ = self.build_index(file_entries)
            index_size = len(index_data)
            hash_size = len(hash_data)
            
            # 更新文件位置信息 (因为索引区和哈希区会插入到文件开头)
            for entry in file_entries:
                entry['start'] += HEADER_SIZE + index_size + hash_size
                entry['end'] += HEADER_SIZE + index_size + hash_size
            
            # 重新构建索引区和哈希区
            index_data, hash_data, index_info = self.build_index(file_entries)
            
            # 写入文件
            self.log(f"正在写入打包文件: {output_file}")
            with open(output_file, 'wb') as f:
                # 写入头部
                f.write(MAGIC_NUMBER)
                f.write(struct.pack('<H', VERSION))
                f.write(struct.pack('<I', index_size))
                f.write(struct.pack('<I', hash_size))
                
                # 写入索引区
                f.write(index_data)
                
                # 写入哈希区
                f.write(hash_data)
                
                # 写入文件数据
                for i, entry in enumerate(file_entries):
                    file_data = entry['data']
                    
                    # 压缩数据
                    if compress:
                        file_data = self.compress_data(file_data)
                    
                    # 加密数据
                    if encryption_key:
                        file_data = self.encrypt_data(file_data, encryption_key)
                    
                    f.write(file_data)
                    
                    if progress_callback:
                        progress_callback(
                            overall=(HEADER_SIZE + index_size + hash_size + entry['start']) / 
                                    (HEADER_SIZE + index_size + hash_size + current_position),
                            file=(i + 1) / len(file_entries),
                            current_file=entry['path']
                        )
            
            self.log("打包完成!")
            return True
        
        except Exception as e:
            self.log(f"打包失败: {str(e)}")
            return False
    
    def unpack_files(self, input_file: str, output_dir: str,
                    encryption_key: Optional[str] = None,
                    compress: bool = False,
                    inspect_only: bool = False,
                    progress_callback: Optional[callable] = None) -> bool:
        """解包.muardo文件"""
        try:
            self.log(f"正在读取打包文件: {input_file}")
            with open(input_file, 'rb') as f:
                # 读取头部
                magic = f.read(6)
                if magic != MAGIC_NUMBER:
                    raise ValueError("无效的.muardo文件")
                
                version = struct.unpack('<H', f.read(2))[0]
                if version != VERSION:
                    raise ValueError(f"不支持的版本: {version}")
                
                index_size = struct.unpack('<I', f.read(4))[0]
                hash_size = struct.unpack('<I', f.read(4))[0]
                
                # 读取索引区
                index_data = f.read(index_size)
                num_entries = index_size // INDEX_ENTRY_SIZE
                
                # 读取哈希区
                hash_data = f.read(hash_size)
                
                # 解析索引
                file_entries = []
                for i in range(num_entries):
                    start, end = struct.unpack('<II', index_data[i*INDEX_ENTRY_SIZE:i*INDEX_ENTRY_SIZE+8])
                    path = index_data[i*INDEX_ENTRY_SIZE+8:i*INDEX_ENTRY_SIZE+264].split(b'\x00')[0].decode('utf-8')
                    file_hash = hash_data[i*HASH_SIZE:(i+1)*HASH_SIZE]
                    
                    file_entries.append({
                        'path': path,
                        'start': start,
                        'end': end,
                        'hash': file_hash
                    })
                
                if inspect_only:
                    self.log("正在检查文件完整性...")
                    all_valid = True
                    
                    for i, entry in enumerate(file_entries):
                        f.seek(entry['start'])
                        file_data = f.read(entry['end'] - entry['start'])
                        
                        if encryption_key:
                            try:
                                file_data = self.decrypt_data(file_data, encryption_key)
                            except Exception as e:
                                self.log(f"文件解密失败: {entry['path']} - {str(e)}")
                                all_valid = False
                                continue
                        
                        if compress:
                            try:
                                file_data = self.decompress_data(file_data)
                            except Exception as e:
                                self.log(f"文件解压失败: {entry['path']} - {str(e)}")
                                all_valid = False
                                continue
                        
                        current_hash = self.calculate_hash(file_data)
                        if current_hash != entry['hash']:
                            self.log(f"文件哈希不匹配: {entry['path']}")
                            all_valid = False
                        
                        if progress_callback:
                            progress_callback(
                                overall=(i + 1) / len(file_entries),
                                file=1.0,
                                current_file=entry['path']
                            )
                    
                    self.log("检查完成!" if all_valid else "发现损坏文件!")
                    return all_valid
                
                # 解包文件
                self.log(f"正在解包到: {output_dir}")
                os.makedirs(output_dir, exist_ok=True)
                
                for i, entry in enumerate(file_entries):
                    output_path = os.path.join(output_dir, entry['path'])
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    
                    f.seek(entry['start'])
                    file_data = f.read(entry['end'] - entry['start'])
                    
                    # 解密数据
                    if encryption_key:
                        file_data = self.decrypt_data(file_data, encryption_key)
                    
                    # 解压数据
                    if compress:
                        file_data = self.decompress_data(file_data)
                    
                    # 验证哈希
                    current_hash = self.calculate_hash(file_data)
                    if current_hash != entry['hash']:
                        self.log(f"警告: 文件哈希不匹配: {entry['path']}")
                    
                    with open(output_path, 'wb') as out_f:
                        out_f.write(file_data)
                    
                    if progress_callback:
                        progress_callback(
                            overall=(i + 1) / len(file_entries),
                            file=1.0,
                            current_file=entry['path']
                        )
                
                self.log("解包完成!")
                return True
        
        except Exception as e:
            self.log(f"解包失败: {str(e)}")
            return False

class MuardoCLI:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description='Muardo 文件打包工具')
        self.setup_arguments()
    
    def setup_arguments(self):
        """设置命令行参数"""
        self.parser.add_argument('-p', '--pack', action='store_true', help='打包文件')
        self.parser.add_argument('-u', '--unpack', action='store_true', help='解包文件')
        self.parser.add_argument('-i', '--inspect', action='store_true', help='只检查文件完整性，不解包')
        self.parser.add_argument('-c', '--compress', action='store_true', help='使用LZ77压缩文件')
        self.parser.add_argument('-e', '--encryption', type=str, help='使用AES加密文件，需要提供密钥')
        self.parser.add_argument('-q', '--quiet', action='store_true', help='静默模式，只输出结果')
        self.parser.add_argument('--CLI', '--no-GUI', action='store_true', help='使用命令行界面')
        self.parser.add_argument('--GUI', '--no-CLI', action='store_true', help='使用图形界面')
        self.parser.add_argument('input', nargs='*', help='输入文件或目录')
        self.parser.add_argument('-o', '--output', help='输出文件或目录')
    
    def run(self):
        """运行命令行界面"""
        args = self.parser.parse_args()
        
        if args.GUI or (not args.CLI and not args.unpack and not args.pack and not args.inspect):
            MuardoGUI().run()
            return
        
        packager = MuardoPackager(args.quiet)
        
        def progress_callback(overall, file, current_file):
            if args.quiet:
                return
            
            # 清空当前行
            sys.stdout.write('\r' + ' ' * 100 + '\r')
            
            # 整体进度条 (50字符宽)
            overall_progress = int(overall * 50)
            sys.stdout.write('整体进度: [' + '#' * overall_progress + ' ' * (50 - overall_progress) + '] ')
            sys.stdout.write(f'{int(overall * 100)}%\n')
            
            # 文件进度条 (50字符宽)
            file_progress = int(file * 50)
            sys.stdout.write('文件进度: [' + '#' * file_progress + ' ' * (50 - file_progress) + '] ')
            sys.stdout.write(f'{int(file * 100)}%\n')
            
            # 当前文件
            sys.stdout.write(f'正在处理: {current_file}\n')
            
            # 移动光标回到第一行
            sys.stdout.write('\033[3A')
            sys.stdout.flush()
        
        if args.pack:
            if not args.input:
                print("错误: 需要指定要打包的文件或目录")
                return
            
            output_file = args.output or 'output.muardo'
            success = packager.pack_files(
                args.input, 
                output_file,
                encryption_key=args.encryption,
                compress=args.compress,
                progress_callback=progress_callback if not args.quiet else None
            )
            
            if not args.quiet:
                sys.stdout.write('\n')
            
            print("打包成功!" if success else "打包失败!")
        
        elif args.unpack or args.inspect:
            if not args.input:
                print("错误: 需要指定要解包或检查的.muardo文件")
                return
            
            output_dir = args.output or 'output'
            success = packager.unpack_files(
                args.input[0],
                output_dir,
                encryption_key=args.encryption,
                compress=args.compress,
                inspect_only=args.inspect,
                progress_callback=progress_callback if not args.quiet else None
            )
            
            if not args.quiet:
                sys.stdout.write('\n')
            
            if args.inspect:
                print("文件完整性检查完成!" if success else "文件完整性检查失败!")
            else:
                print("解包成功!" if success else "解包失败!")
        
        else:
            self.parser.print_help()

class MuardoGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Muardo 文件打包工具")
        self.setup_ui()
        self.packager = MuardoPackager(quiet=True)
    
    def setup_ui(self):
        """设置图形用户界面"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 模式选择
        mode_frame = ttk.LabelFrame(main_frame, text="操作模式", padding="10")
        mode_frame.pack(fill=tk.X, pady=5)
        
        self.mode_var = tk.StringVar(value="pack")
        ttk.Radiobutton(mode_frame, text="打包", variable=self.mode_var, value="pack").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="解包", variable=self.mode_var, value="unpack").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="检查", variable=self.mode_var, value="inspect").pack(side=tk.LEFT, padx=5)
        
        # 输入设置
        input_frame = ttk.LabelFrame(main_frame, text="输入", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        
        self.input_entry = ttk.Entry(input_frame)
        self.input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(input_frame, text="浏览...", command=self.browse_input).pack(side=tk.LEFT, padx=5)
        
        # 输出设置
        output_frame = ttk.LabelFrame(main_frame, text="输出", padding="10")
        output_frame.pack(fill=tk.X, pady=5)
        
        self.output_entry = ttk.Entry(output_frame)
        self.output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(output_frame, text="浏览...", command=self.browse_output).pack(side=tk.LEFT, padx=5)
        
        # 选项设置
        options_frame = ttk.LabelFrame(main_frame, text="选项", padding="10")
        options_frame.pack(fill=tk.X, pady=5)
        
        self.compress_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="压缩(LZ77)", variable=self.compress_var).pack(anchor=tk.W)
        
        self.encrypt_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="加密(AES)", variable=self.encrypt_var, 
                       command=self.toggle_encryption).pack(anchor=tk.W)
        
        self.key_entry = ttk.Entry(options_frame, show="*", state=tk.DISABLED)
        self.key_entry.pack(fill=tk.X, pady=5)
        
        # 进度条
        progress_frame = ttk.LabelFrame(main_frame, text="进度", padding="10")
        progress_frame.pack(fill=tk.X, pady=5)
        
        self.overall_label = ttk.Label(progress_frame, text="整体进度:")
        self.overall_label.pack(anchor=tk.W)
        self.overall_progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.overall_progress.pack(fill=tk.X, pady=5)
        
        self.file_label = ttk.Label(progress_frame, text="文件进度:")
        self.file_label.pack(anchor=tk.W)
        self.file_progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.file_progress.pack(fill=tk.X, pady=5)
        
        self.current_file = ttk.Label(progress_frame, text="当前文件: 无")
        self.current_file.pack(anchor=tk.W)
        
        # 操作按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="开始", command=self.start_operation).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="退出", command=self.root.quit).pack(side=tk.RIGHT, padx=5)
    
    def toggle_encryption(self):
        """切换加密选项状态"""
        if self.encrypt_var.get():
            self.key_entry.config(state=tk.NORMAL)
        else:
            self.key_entry.config(state=tk.DISABLED)
    
    def browse_input(self):
        """浏览输入文件或目录"""
        mode = self.mode_var.get()
        if mode == "pack":
            paths = filedialog.askopenfilenames(title="选择要打包的文件")
            if paths:
                self.input_entry.delete(0, tk.END)
                self.input_entry.insert(0, ";".join(paths))
        else:
            path = filedialog.askopenfilename(title="选择.muardo文件", filetypes=[("Muardo 文件", "*.muardo")])
            if path:
                self.input_entry.delete(0, tk.END)
                self.input_entry.insert(0, path)
    
    def browse_output(self):
        """浏览输出文件或目录"""
        mode = self.mode_var.get()
        if mode == "pack":
            path = filedialog.asksaveasfilename(
                title="保存为.muardo文件",
                defaultextension=".muardo",
                filetypes=[("Muardo 文件", "*.muardo")]
            )
            if path:
                self.output_entry.delete(0, tk.END)
                self.output_entry.insert(0, path)
        else:
            path = filedialog.askdirectory(title="选择解包目录")
            if path:
                self.output_entry.delete(0, tk.END)
                self.output_entry.insert(0, path)
    
    def update_progress(self, overall, file, current_file):
        """更新进度条"""
        self.overall_progress['value'] = overall * 100
        self.file_progress['value'] = file * 100
        self.current_file.config(text=f"当前文件: {current_file}")
        self.root.update()
    
    def start_operation(self):
        """开始打包/解包/检查操作"""
        input_path = self.input_entry.get()
        output_path = self.output_entry.get()
        
        if not input_path:
            messagebox.showerror("错误", "请指定输入文件或目录")
            return
        
        if not output_path and self.mode_var.get() != "inspect":
            messagebox.showerror("错误", "请指定输出文件或目录")
            return
        
        encryption_key = self.key_entry.get() if self.encrypt_var.get() else None
        compress = self.compress_var.get()
        
        # 重置进度条
        self.overall_progress['value'] = 0
        self.file_progress['value'] = 0
        self.current_file.config(text="当前文件: 无")
        self.root.update()
        
        try:
            if self.mode_var.get() == "pack":
                input_paths = input_path.split(";")
                success = self.packager.pack_files(
                    input_paths,
                    output_path,
                    encryption_key=encryption_key,
                    compress=compress,
                    progress_callback=self.update_progress
                )
                
                if success:
                    messagebox.showinfo("成功", "文件打包完成!")
                else:
                    messagebox.showerror("错误", "文件打包失败!")
            
            else:
                inspect_only = (self.mode_var.get() == "inspect")
                success = self.packager.unpack_files(
                    input_path,
                    output_path if not inspect_only else "",
                    encryption_key=encryption_key,
                    compress=compress,
                    inspect_only=inspect_only,
                    progress_callback=self.update_progress
                )
                
                if inspect_only:
                    if success:
                        messagebox.showinfo("成功", "所有文件完整性检查通过!")
                    else:
                        messagebox.showwarning("警告", "发现损坏文件!")
                else:
                    if success:
                        messagebox.showinfo("成功", "文件解包完成!")
                    else:
                        messagebox.showerror("错误", "文件解包失败!")
        
        except Exception as e:
            messagebox.showerror("错误", f"操作失败: {str(e)}")
    
    def run(self):
        """运行GUI"""
        self.root.mainloop()

if __name__ == '__main__':
    MuardoCLI().run()
