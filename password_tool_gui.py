import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import hashlib
import itertools
import string
from datetime import datetime
import os
import threading
import re

class PasswordAnalyzer:
    def __init__(self, common_passwords_file='common_passwords.txt'):
        self.common_passwords = self.load_common_passwords(common_passwords_file)
    
    def load_common_passwords(self, filename):
        common_passwords = set()
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    common_passwords.add(line.strip().lower())
        except FileNotFoundError:
            print(f"Warning: {filename} not found. Common password check disabled.")
        return common_passwords
    
    def analyze_password(self, password):
        results = {
            'password': password,
            'length': len(password),
            'has_upper': any(c.isupper() for c in password),
            'has_lower': any(c.islower() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_special': any(not c.isalnum() for c in password),
            'is_common': password.lower() in self.common_passwords,
            'score': 0,
            'strength': 'Very Weak'
        }
        
        # Calculate score
        results['score'] += min(results['length'] * 4, 40)
        if results['has_upper']: results['score'] += 10
        if results['has_lower']: results['score'] += 10
        if results['has_digit']: results['score'] += 10
        if results['has_special']: results['score'] += 15
        if results['is_common']: results['score'] = max(0, results['score'] - 50)
        
        # Determine strength
        if results['score'] >= 80:
            results['strength'] = 'Very Strong'
        elif results['score'] >= 60:
            results['strength'] = 'Strong'
        elif results['score'] >= 40:
            results['strength'] = 'Moderate'
        elif results['score'] >= 20:
            results['strength'] = 'Weak'
        
        return results

class WordlistGenerator:
    def generate_wordlist(self, user_info, output_file='custom_wordlist.txt', max_length=8):
        words = set()
        base_words = []
        
        for key, value in user_info.items():
            if value:
                if isinstance(value, str):
                    base_words.extend(value.split())
                    base_words.append(value)
                elif isinstance(value, (int, float)):
                    base_words.append(str(value))
        
        base_words = list(set(base_words))
        
        for word in base_words:
            if word:
                words.add(word)
                words.add(word.lower())
                words.add(word.upper())
                words.add(word.capitalize())
                
                substituted = word.lower()
                substituted = substituted.replace('a', '@')
                substituted = substituted.replace('s', '$')
                substituted = substituted.replace('i', '!')
                substituted = substituted.replace('o', '0')
                substituted = substituted.replace('e', '3')
                words.add(substituted)
        
        for i in range(1, min(3, len(base_words)) + 1):
            for combo in itertools.combinations(base_words, i):
                combined = ''.join(combo)
                if 3 <= len(combined) <= max_length:
                    words.add(combined)
                    words.add(combined.lower())
                    words.add(combined.upper())
        
        numbers = ['123', '1234', '12345', '123456', '111', '222', '333', '444', '555', 
                  '666', '777', '888', '999', '000', '007', '69', '420']
        special_combos = ['!', '@', '#', '$', '%', '&', '*', '!!', '!!!', '!@#', '#$%']
        
        temp_words = list(words)
        for word in temp_words:
            for number in numbers:
                if len(word + number) <= max_length:
                    words.add(word + number)
                    words.add(number + word)
            for special in special_combos:
                if len(word + special) <= max_length:
                    words.add(word + special)
                    words.add(special + word)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for word in sorted(words, key=len):
                if 3 <= len(word) <= max_length:
                    f.write(word + '\n')
        
        return len(words)

class PasswordCracker:
    def __init__(self):
        self.attempts = 0
        self.stop_cracking = False
    
    def crack_md5(self, target_hash, wordlist_file, salt=None, progress_callback=None):
        start_time = datetime.now()
        self.attempts = 0
        self.stop_cracking = False
        
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                total_lines = sum(1 for _ in f)
                f.seek(0)
                
                for i, password in enumerate(f):
                    if self.stop_cracking:
                        return {'found': False, 'stopped': True}
                    
                    password = password.strip()
                    self.attempts += 1
                    
                    if salt:
                        test_string = salt + password
                    else:
                        test_string = password
                    
                    hashed = hashlib.md5(test_string.encode()).hexdigest()
                    
                    if progress_callback and i % 100 == 0:
                        progress_callback(i / total_lines * 100)
                    
                    if hashed == target_hash:
                        end_time = datetime.now()
                        time_taken = (end_time - start_time).total_seconds()
                        return {
                            'found': True,
                            'password': password,
                            'attempts': self.attempts,
                            'time_taken': time_taken,
                            'salt_used': salt is not None
                        }
        
        except FileNotFoundError:
            return {'found': False, 'error': 'Wordlist file not found'}
        
        end_time = datetime.now()
        time_taken = (end_time - start_time).total_seconds()
        return {
            'found': False,
            'attempts': self.attempts,
            'time_taken': time_taken,
            'salt_used': salt is not None
        }

class ModernPasswordToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Password Security Toolkit Pro")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f8ff')
        
        self.colors = {
            'primary': '#2c3e50',
            'secondary': '#3498db',
            'accent': '#e74c3c',
            'success': '#27ae60',
            'warning': '#f39c12',
            'light': '#ecf0f1',
            'dark': '#2c3e50',
            'background': '#f0f8ff'
        }
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        self.analyzer = PasswordAnalyzer()
        self.generator = WordlistGenerator()
        self.cracker = PasswordCracker()
        self._password_visible = False
        
        self.setup_ui()
        self.create_menu()
    
    def configure_styles(self):
        self.style.configure('TFrame', background=self.colors['background'])
        self.style.configure('TLabel', background=self.colors['background'], foreground=self.colors['dark'])
        self.style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground=self.colors['primary'])
        self.style.configure('Header.TLabel', font=('Arial', 12, 'bold'), foreground=self.colors['secondary'])
        self.style.configure('TButton', font=('Arial', 10), padding=6)
        self.style.configure('Primary.TButton', background=self.colors['secondary'], foreground='white')
        self.style.configure('Success.TButton', background=self.colors['success'], foreground='white')
        self.style.configure('Warning.TButton', background=self.colors['warning'], foreground='white')
        self.style.configure('Accent.TButton', background=self.colors['accent'], foreground='white')
        self.style.map('Primary.TButton', background=[('active', self.colors['primary'])])
        self.style.map('Success.TButton', background=[('active', '#219955')])
    
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(fill='both', expand=True)
        
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill='x', pady=(0, 20))
        
        title_label = ttk.Label(header_frame, text="🔒 Password Security Toolkit Pro", style='Title.TLabel')
        title_label.pack()
        
        subtitle_label = ttk.Label(header_frame, text="Analyze, Generate, and Learn About Password Security", style='Header.TLabel')
        subtitle_label.pack()
        
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill='both', expand=True)
        
        analyze_frame = ttk.Frame(notebook, padding=20)
        generate_frame = ttk.Frame(notebook, padding=20)
        crack_frame = ttk.Frame(notebook, padding=20)
        about_frame = ttk.Frame(notebook, padding=20)
        
        notebook.add(analyze_frame, text='🔍 Password Analysis')
        notebook.add(generate_frame, text='📝 Wordlist Generator')
        notebook.add(crack_frame, text='🔓 Password Cracker')
        notebook.add(about_frame, text='ℹ️ About')
        
        self.setup_analyze_tab(analyze_frame)
        self.setup_generate_tab(generate_frame)
        self.setup_crack_tab(crack_frame)
        self.setup_about_tab(about_frame)
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Check Common Passwords", command=self.show_common_passwords)
        tools_menu.add_command(label="Password Tips", command=self.show_password_tips)
    
    def setup_analyze_tab(self, frame):
        ttk.Label(frame, text="Password Strength Analyzer", style='Header.TLabel').pack(pady=(0, 15))
        
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill='x', pady=10)
        
        ttk.Label(input_frame, text="Enter Password:", font=('Arial', 10, 'bold')).pack(anchor='w')
        
        password_frame = ttk.Frame(input_frame)
        password_frame.pack(fill='x', pady=5)
        
        self.password_var = tk.StringVar()
        self.password_var.trace('w', self.realtime_analysis)
        
        password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show='•', font=('Arial', 12), width=30)
        password_entry.pack(side='left', padx=(0, 10))
        
        btn_frame = ttk.Frame(password_frame)
        btn_frame.pack(side='left')
        
        ttk.Button(btn_frame, text="👁", width=3, command=self.toggle_password_visibility).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="Analyze", style='Primary.TButton', command=self.analyze_password).pack(side='left', padx=2)
        ttk.Button(btn_frame, text="Clear", command=self.clear_analysis).pack(side='left', padx=2)
        
        strength_frame = ttk.Frame(frame)
        strength_frame.pack(fill='x', pady=10)
        
        ttk.Label(strength_frame, text="Strength Meter:", font=('Arial', 10, 'bold')).pack(anchor='w')
        
        self.strength_bar = ttk.Progressbar(strength_frame, mode='determinate', length=400)
        self.strength_bar.pack(fill='x', pady=5)
        
        self.strength_label = ttk.Label(strength_frame, text="Enter a password to begin analysis", font=('Arial', 10))
        self.strength_label.pack()
        
        ttk.Label(frame, text="Detailed Analysis:", font=('Arial', 10, 'bold')).pack(anchor='w', pady=(15, 5))
        
        results_frame = ttk.Frame(frame)
        results_frame.pack(fill='both', expand=True, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=12, width=80, font=('Consolas', 10), bg='#ffffff', relief='solid', borderwidth=1)
        self.results_text.pack(fill='both', expand=True)
        self.results_text.config(state='disabled')
    
    def setup_generate_tab(self, frame):
        ttk.Label(frame, text="Smart Wordlist Generator", style='Header.TLabel').pack(pady=(0, 15))
        
        input_grid = ttk.Frame(frame)
        input_grid.pack(fill='x', pady=10)
        
        fields = [
            ('👤 Full Name', 'name_var'),
            ('🎂 Birth Year', 'birthyear_var'),
            ('🐾 Pet Name', 'pet_var'),
            ('🏢 Company', 'company_var'),
            ('⭐ Other Keywords', 'keywords_var'),
            ('📅 Important Dates', 'dates_var')
        ]
        
        for i, (label, var_name) in enumerate(fields):
            row = i % 3
            col = i // 3
            frame_cell = ttk.Frame(input_grid)
            frame_cell.grid(row=row, column=col, padx=10, pady=5, sticky='w')
            
            ttk.Label(frame_cell, text=label, font=('Arial', 9)).pack(anchor='w')
            setattr(self, var_name, tk.StringVar())
            ttk.Entry(frame_cell, textvariable=getattr(self, var_name), width=20).pack(anchor='w')
        
        options_frame = ttk.Frame(frame)
        options_frame.pack(fill='x', pady=15)
        
        ttk.Label(options_frame, text="Options:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w')
        
        ttk.Label(options_frame, text="Max Length:").grid(row=1, column=0, sticky='w', pady=2)
        self.max_length_var = tk.StringVar(value="12")
        ttk.Spinbox(options_frame, from_=4, to=20, textvariable=self.max_length_var, width=5).grid(row=1, column=1, padx=5)
        
        ttk.Label(options_frame, text="Output File:").grid(row=1, column=2, sticky='w', padx=(20,0))
        self.output_file_var = tk.StringVar(value="custom_wordlist.txt")
        ttk.Entry(options_frame, textvariable=self.output_file_var, width=20).grid(row=1, column=3, padx=5)
        ttk.Button(options_frame, text="Browse", command=self.browse_output_file).grid(row=1, column=4, padx=5)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="🛠️ Generate Wordlist", style='Success.TButton', command=self.generate_wordlist).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="📊 Preview Patterns", command=self.preview_patterns).pack(side='left', padx=5)
        
        self.generate_status = ttk.Label(frame, text="Ready to generate", font=('Arial', 9))
        self.generate_status.pack(pady=5)
    
    def setup_crack_tab(self, frame):
        ttk.Label(frame, text="Educational MD5 Cracker", style='Header.TLabel').pack(pady=(0, 15))
        
        input_frame = ttk.Frame(frame)
        input_frame.pack(fill='x', pady=10)
        
        ttk.Label(input_frame, text="Target MD5 Hash:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', pady=2)
        self.hash_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.hash_var, width=40, font=('Consolas', 10)).grid(row=0, column=1, padx=5)
        ttk.Button(input_frame, text="Paste", command=self.paste_hash).grid(row=0, column=2, padx=5)
        
        ttk.Label(input_frame, text="Wordlist File:", font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky='w', pady=2)
        self.wordlist_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.wordlist_var, width=30).grid(row=1, column=1, padx=5)
        ttk.Button(input_frame, text="Browse", command=self.browse_wordlist).grid(row=1, column=2, padx=5)
        
        ttk.Label(input_frame, text="Salt (optional):", font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky='w', pady=2)
        self.salt_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.salt_var, width=20).grid(row=2, column=1, padx=5)
        
        progress_frame = ttk.Frame(frame)
        progress_frame.pack(fill='x', pady=15)
        
        ttk.Label(progress_frame, text="Progress:", font=('Arial', 10, 'bold')).pack(anchor='w')
        
        self.progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        progress_bar.pack(fill='x', pady=5)
        
        self.progress_label = ttk.Label(progress_frame, text="0%")
        self.progress_label.pack()
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="🚀 Start Cracking", style='Primary.TButton', command=self.start_cracking).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="⏹️ Stop", style='Accent.TButton', command=self.stop_cracking).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="📋 Copy Results", command=self.copy_results).pack(side='left', padx=5)
        
        ttk.Label(frame, text="Results:", font=('Arial', 10, 'bold')).pack(anchor='w', pady=(15, 5))
        
        self.crack_results = scrolledtext.ScrolledText(frame, height=10, font=('Consolas', 9), bg='#f8f9fa', relief='solid', borderwidth=1)
        self.crack_results.pack(fill='both', expand=True, pady=5)
        self.crack_results.config(state='disabled')
    
    def setup_about_tab(self, frame):
        ttk.Label(frame, text="About Password Security Toolkit", style='Header.TLabel').pack(pady=(0, 15))
        
        about_text = """🔒 Password Security Toolkit Pro

Version: 2.0
Created for educational purposes only

This tool helps you:
• Analyze password strength and get recommendations
• Generate targeted wordlists for security testing
• Understand MD5 cracking concepts (educational only)

⚠️ SECURITY WARNING:
This tool is for EDUCATIONAL PURPOSES only.
Use only on systems you own or have permission to test.

Features:
• Real-time password strength analysis
• Smart wordlist generation with common patterns
• Educational MD5 cracking demonstration
• Modern, user-friendly interface

Built with Python and Tkinter"""
        
        about_label = ttk.Label(frame, text=about_text, justify='left', font=('Arial', 10))
        about_label.pack(pady=10)
        
        ttk.Separator(frame, orient='horizontal').pack(fill='x', pady=20)
        ttk.Label(frame, text="💡 Remember: Use strong, unique passwords for every account!", font=('Arial', 9, 'italic')).pack()

    # FUNCTIONAL METHODS START HERE
    def toggle_password_visibility(self):
        current = self.password_var.get()
        if hasattr(self, '_password_visible') and self._password_visible:
            self.password_var.set('•' * len(current))
            self._password_visible = False
        else:
            self.password_var.set(current)
            self._password_visible = True

    def realtime_analysis(self, *args):
        password = self.password_var.get()
        if not password:
            self.strength_bar['value'] = 0
            self.strength_label.config(text="Enter a password to begin analysis")
            return
        
        result = self.analyzer.analyze_password(password)
        self.strength_bar['value'] = result['score']
        self.strength_label.config(text=f"Strength: {result['strength']} ({result['score']}/100)")

    def analyze_password(self):
        password = self.password_var.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password to analyze")
            return
        
        result = self.analyzer.analyze_password(password)
        
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        
        output = f"""Password Analysis Results:
──────────────────────────
Password: {result['password']}
Length: {result['length']} characters
Contains uppercase: {result['has_upper']}
Contains lowercase: {result['has_lower']}
Contains digits: {result['has_digit']}
Contains special chars: {result['has_special']}
Is common password: {result['is_common']}

Strength score: {result['score']}/100
Strength: {result['strength']}

Recommendations:
────────────────"""
        
        recommendations = []
        if result['length'] < 8:
            recommendations.append("• Use at least 8 characters")
        if not result['has_upper']:
            recommendations.append("• Add uppercase letters")
        if not result['has_lower']:
            recommendations.append("• Add lowercase letters")
        if not result['has_digit']:
            recommendations.append("• Add numbers")
        if not result['has_special']:
            recommendations.append("• Add special characters")
        if result['is_common']:
            recommendations.append("• Avoid common passwords")
        
        if not recommendations:
            recommendations.append("• Good job! Your password is strong")
        
        output += "\n" + "\n".join(recommendations)
        
        self.results_text.insert(tk.END, output)
        self.results_text.config(state='disabled')

    def clear_analysis(self):
        self.password_var.set("")
        self.results_text.config(state='normal')
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state='disabled')
        self.strength_bar['value'] = 0
        self.strength_label.config(text="Enter a password to begin analysis")

    def browse_output_file(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.output_file_var.set(filename)

    def browse_wordlist(self):
        filename = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.wordlist_var.set(filename)

    def paste_hash(self):
        try:
            clipboard = self.root.clipboard_get()
            if len(clipboard) == 32 and all(c in '0123456789abcdefABCDEF' for c in clipboard):
                self.hash_var.set(clipboard)
            else:
                messagebox.showwarning("Warning", "Clipboard doesn't contain a valid MD5 hash")
        except:
            messagebox.showwarning("Warning", "Could not get content from clipboard")

    def generate_wordlist(self):
        user_info = {
            'name': self.name_var.get(),
            'birthyear': self.birthyear_var.get(),
            'pet': self.pet_var.get(),
            'company': self.company_var.get(),
            'keywords': self.keywords_var.get(),
            'dates': self.dates_var.get()
        }
        
        all_info = []
        for value in user_info.values():
            if value:
                all_info.extend(value.split())
        
        if not all_info:
            messagebox.showerror("Error", "Please provide at least one piece of information")
            return
        
        try:
            max_length = int(self.max_length_var.get())
            output_file = self.output_file_var.get()
            
            count = self.generator.generate_wordlist(
                {'info': ' '.join(all_info)},
                output_file,
                max_length
            )
            
            self.generate_status.config(text=f"Generated {count} passwords in {output_file}")
            messagebox.showinfo("Success", f"Generated {count} passwords in {output_file}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate wordlist: {str(e)}")

    def preview_patterns(self):
        messagebox.showinfo("Pattern Preview", 
            "The generator will create variations including:\n\n"
            "• Uppercase/lowercase versions\n• Common substitutions (@ for a, $ for s, etc.)\n"
            "• Number suffixes (123, 1234, etc.)\n• Special character combinations\n"
            "• Combinations of multiple words")

    def start_cracking(self):
        target_hash = self.hash_var.get().strip()
        wordlist_file = self.wordlist_var.get()
        salt = self.salt_var.get().strip() or None
        
        if not target_hash or len(target_hash) != 32:
            messagebox.showerror("Error", "Please enter a valid 32-character MD5 hash")
            return
        
        if not wordlist_file:
            messagebox.showerror("Error", "Please select a wordlist file")
            return
        
        def crack_thread():
            self.progress_var.set(0)
            self.update_crack_results("Starting cracking process...\n")
            
            result = self.cracker.crack_md5(
                target_hash, wordlist_file, salt,
                lambda p: self.progress_var.set(p)
            )
            
            if result.get('found'):
                output = f"""Password found!
────────────────
Password: {result['password']}
Attempts: {result['attempts']:,}
Time taken: {result['time_taken']:.2f} seconds"""
                if result['salt_used']:
                    output += f"\nSalt used: {salt}"
            elif result.get('stopped'):
                output = "Cracking stopped by user"
            else:
                output = f"""Password not found
────────────────
Attempts: {result['attempts']:,}
Time taken: {result['time_taken']:.2f} seconds"""
                if result.get('error'):
                    output += f"\nError: {result['error']}"
            
            self.update_crack_results(output + "\n")
        
        threading.Thread(target=crack_thread, daemon=True).start()

    def stop_cracking(self):
        self.cracker.stop_cracking = True
        self.update_crack_results("Stopping cracking process...\n")

    def copy_results(self):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.crack_results.get(1.0, tk.END))
            messagebox.showinfo("Success", "Results copied to clipboard!")
        except:
            messagebox.showerror("Error", "Could not copy to clipboard")

    def update_crack_results(self, text):
        self.root.after(0, lambda: self._update_crack_results(text))

    def _update_crack_results(self, text):
        self.crack_results.config(state='normal')
        self.crack_results.insert(tk.END, text + "\n")
        self.crack_results.see(tk.END)
        self.crack_results.config(state='disabled')
        self.progress_label.config(text=f"{int(self.progress_var.get())}%")

    def show_common_passwords(self):
        messagebox.showinfo("Common Passwords", 
            "Top 10 most common passwords to avoid:\n\n"
            "1. password\n2. 123456\n3. 12345678\n4. qwerty\n5. abc123\n"
            "6. password1\n7. 12345\n8. 123456789\n9. letmein\n10. welcome")

    def show_password_tips(self):
        messagebox.showinfo("Password Tips",
            "🔒 Strong Password Tips:\n\n"
            "• Use at least 12 characters\n• Mix uppercase and lowercase letters\n"
            "• Include numbers and special characters\n• Avoid dictionary words\n"
            "• Don't use personal information\n• Use a passphrase instead\n"
            "• Use a password manager\n• Enable two-factor authentication")

def main():
    root = tk.Tk()
    app = ModernPasswordToolGUI(root)
    
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (900 // 2)
    y = (root.winfo_screenheight() // 2) - (700 // 2)
    root.geometry(f'900x700+{x}+{y}')
    
    root.mainloop()

if __name__ == "__main__":
    main()