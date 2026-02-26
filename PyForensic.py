from config import script_directory
from tkinter.messagebox import showwarning
from softwares import softwares
from pathlib import Path
from functools import partial
from tkinterdnd2 import DND_FILES, TkinterDnD
from PIL import Image
from plugins.malware import malware
from plugins.process import process 
from plugins.network import network
from plugins.registry import registry 
from plugins.dll import dll
from plugins.memory import memory
from plugins.kernel import kernel
from plugins.info import info
from security.ip import ip
from security.url import url
from security.analyze import Analyze
from proxy.proxy import proxy

import requests
import threading
import customtkinter as ctk
import pywinstyles
import pygame
import random

class PyForensic:

    softwares()

    def __init__(self):

        pygame.mixer.init()

        icons_directory = script_directory / "icons"

        self.icons = {}

        if icons_directory.exists():

            for icon in icons_directory.iterdir():

                if icon.suffix == ".png":

                    name = icon.stem
                    
                    icon_path = icon
                    img = Image.open(icon_path)

                    self.icons[name] = ctk.CTkImage(

                        light_image=img,
                        dark_image=img,
                        size=(24, 24)

                        )

        self.pyforensic_title = "PyForensic :"

        self.upload_label = "Please upload a directory containing all the binaries to be analyzed"

        self.pyforensic = TkinterDnD.Tk()
        self.pyforensic.withdraw()

        self.pyforensic.title(self.pyforensic_title)
        self.pyforensic.attributes("-alpha", 0.0)
        
        self.pyforensic.configure(bg="#242424") 
        
        window_width = 1150
        window_height = 630

        screen_width = self.pyforensic.winfo_screenwidth()
        screen_height = self.pyforensic.winfo_screenheight()

        center_x = int(screen_width / 2 - window_width / 2)
        center_y = int(screen_height / 2 - window_height / 2)
        
        self.pyforensic.geometry(f"{window_width}x{window_height}+{center_x}+{center_y}")
        self.pyforensic.resizable(False, False)

        pywinstyles.change_header_color(self.pyforensic, "#202020")

        self.calibri_bold = ctk.CTkFont("Calibri", 15, "bold")

        self.volatility_label = ctk.CTkLabel(

            self.pyforensic,
            text="VOLATILITY :",
            font=self.calibri_bold

            )
        
        self.volatility_label.place(x=10, y=5)

        self.buttons("malware", "MALWARE", 40, partial(self.informations, malware))
        self.buttons("process", "PROCESS", 85, partial(self.informations, process))
        self.buttons("network", "NETWORK", 130, partial(self.informations, network))
        self.buttons("registry", "REGISTRY", 175, partial(self.informations, registry))
        self.buttons("dll", "DLL", 220, partial(self.informations, dll))
        self.buttons("memory", "MEMORY", 265, partial(self.informations, memory))
        self.buttons("kernel", "KERNEL", 310, partial(self.informations, kernel))
        self.buttons("info", "INFO", 355, partial(self.informations, info))

        self.antivirus_label = ctk.CTkLabel(

            self.pyforensic,
            text="ANTIVIRUS :",
            font=self.calibri_bold

            )
        
        self.antivirus_label.place(x=10, y=408)

        self.buttons("analyze", "ANALYZE", 445, self.binary_analysis)
        self.buttons("proxy", "PROXY", 490, lambda: threading.Thread(target=proxy, daemon=True).start())
        self.buttons("ip", "IP", 535, partial(self.informations, ip))
        self.buttons("url", "URL", 580, partial(self.informations, url))

        self.music_icon_label = ctk.CTkLabel(

            self.pyforensic,
            text="",
            image=self.icons.get("music")

            )

        self.music_icon_label.place(x=370, y=5)

        self.music_switch = ctk.CTkSwitch(

            self.pyforensic,
            text="",
            width=45,
            command=self.toggle_music,
            fg_color="#555555",
            progress_color="#708090"

            )

        self.music_switch.select()
        self.music_switch.place(x=405, y=5)

        self.result_frame = ctk.CTkFrame(

            self.pyforensic,
            width=770,
            height=580,
            corner_radius=15,
            border_width=2,
            fg_color="#242424",
            border_color="#555555"

            )
        
        self.result_frame.place(x=370, y=40)

        self.result_textbox = ctk.CTkTextbox(

            self.result_frame,
            width=750,
            height=560,
            corner_radius=10,
            font=self.calibri_bold,
            fg_color="#1e1e1e",
            scrollbar_button_color="#1e1e1e",
            scrollbar_button_hover_color="#1e1e1e",
            state="disabled",
            wrap="none"

            )
        
        self.result_textbox.place(x=10, y=10)

        self.drop_label = ctk.CTkLabel(

            self.result_textbox,
            text=self.upload_label + ".",
            font=self.calibri_bold,
            corner_radius=15

            )
        
        self.drop_label.place(relx=0.5, rely=0.5, anchor="center")

        self.drop_label.drop_target_register(DND_FILES)
        self.drop_label.dnd_bind("<<Drop>>", self.drag_drop)

        self.is_running = False
        self.stop_event = threading.Event()

        self.pyforensic.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.pyforensic.deiconify()
        self.pyforensic.after(1000, lambda: self.pyforensic.attributes("-alpha", 1.0))
        
        self.pyforensic.mainloop()

    def play_music(self):

        if self.music_switch.get() == 0:

            return

        music_directory = script_directory / "music"

        if music_directory.exists():

            musics = []
            
            for music in music_directory.iterdir():

                if music.suffix == ".mp3" or music.suffix == ".wav":

                    musics.append(music)

            if musics:

                chosen_music = random.choice(musics)
                music_path = str(chosen_music)
                
                pygame.mixer.music.load(music_path)
                pygame.mixer.music.play()

    def toggle_music(self):

        if self.music_switch.get() == 0:

            pygame.mixer.music.stop()

        else:

            self.play_music()

    def on_closing(self):

        pygame.mixer.music.stop()
        self.stop_event.set()
        self.pyforensic.destroy()

    def validate_numbers(self, P):

        if P == "":
            
            return True

        if P.isdigit() and len(P) <= 3:
            
            return True

        return False

    def start_move(self, event, window):

        window.x = event.x
        window.y = event.y

    def stop_move(self, event):

        None

    def on_move(self, event, window):

        delta_x = event.x - window.x
        delta_y = event.y - window.y
        
        x = window.winfo_x() + delta_x
        y = window.winfo_y() + delta_y

        window.geometry(f"+{x}+{y}")

    def submit_duration(self, entry, window):

        self.duration_value = entry.get()
        window.destroy()

    def ask_duration(self):

        while True:

            time_dialog = ctk.CTkToplevel(self.pyforensic)
            time_dialog.title(self.pyforensic_title)
            
            toplevel_width = 350
            toplevel_height = 180

            screen_width = time_dialog.winfo_screenwidth()
            screen_height = time_dialog.winfo_screenheight()
            
            toplevel_x = int(screen_width / 2 - toplevel_width / 2)
            toplevel_y = int(screen_height / 2 - toplevel_height / 2)
            
            time_dialog.geometry(f"{toplevel_width}x{toplevel_height}+{toplevel_x}+{toplevel_y}")
            time_dialog.resizable(False, False)
            time_dialog.overrideredirect(True)
            time_dialog.attributes("-topmost", True)

            if ctk.get_appearance_mode() == "Dark":

                background_color = "#242424"
            
            else:

                background_color = "#ebebeb"

            time_dialog.configure(fg_color=background_color)
            time_dialog.attributes("-transparentcolor", background_color)

            time_frame = ctk.CTkFrame(

                time_dialog, 
                corner_radius=15, 
                width=350, 
                height=180, 
                border_width=2,
                border_color="#555555"
            
                )
            
            time_frame.pack(fill="both", expand=True)

            time_dialog.bind("<ButtonPress-1>", lambda event: self.start_move(event, time_dialog))
            time_dialog.bind("<ButtonRelease-1>", self.stop_move)
            time_dialog.bind("<B1-Motion>", lambda event: self.on_move(event, time_dialog))

            title_label = ctk.CTkLabel(time_frame, text=self.pyforensic_title, font=self.calibri_bold)
            title_label.pack(pady=(10, 0))

            label = ctk.CTkLabel(time_frame, text="How long do you want the results to remain displayed ?")
            label.pack(pady=10)

            valid_time = (self.pyforensic.register(self.validate_numbers), '%P')

            entry = ctk.CTkEntry(time_frame, validate='key', validatecommand=valid_time)
            entry.pack(pady=5)
            entry.focus_set()

            self.duration_value = None

            ok_button = ctk.CTkButton(time_frame, text="OK", command=partial(self.submit_duration, entry, time_dialog), corner_radius=15)
            ok_button.pack(pady=15)

            time_dialog.grab_set()
            self.pyforensic.wait_window(time_dialog)

            duration = self.duration_value

            try:

                if duration and int(duration) > 0:

                    self.display_duration = int(duration) * 1000
                    break

                else:

                    showwarning(title=self.pyforensic_title, message="Please select a duration ; this is mandatory !")

            except (ValueError, TypeError):

                showwarning(title=self.pyforensic_title, message="Please only submit durations using numbers !")

    def update_result(self, text, clear=False):

        def apply():

            self.result_textbox.configure(state="normal")

            if clear:

                self.result_textbox.delete("1.0", "end")

            current_content = self.result_textbox.get("1.0", "end-1c")

            if current_content == "":
                
                self.result_textbox.insert("end", text)
            
            else:

                self.result_textbox.insert("end", text)

            self.result_textbox.see("end")
            self.result_textbox.configure(state="disabled")

        if not self.stop_event.is_set():
            self.pyforensic.after(0, apply)

    def buttons(self, name, text, y_pos, command=None):

        button = ctk.CTkButton(

            self.pyforensic,
            text=text,
            font=self.calibri_bold,
            image=self.icons.get(name),
            width=350,
            height=40,
            corner_radius=15,
            border_width=2,
            border_spacing=2,
            hover_color="#708090",
            border_color="#555555",
            fg_color="#242424",
            command=command

            )

        button.place(x=10, y=y_pos)

        setattr(self, f"{name}_button", button)

    def drag_drop(self, event):

        self.path = Path(event.data.strip("{}"))

        binary_count = 0

        if self.path.is_dir():

            for binary in self.path.iterdir():
        
                if binary.suffix.lower() == ".exe": 

                    binary_count += 1

        if binary_count >= 2:

            self.drop_label.configure(text=f"All binaries in : {self.path.name} can be analyzed !")

        else:

            self.drop_label.configure(text="Please transmit a directory containing at least two binary files for analys !")

    def clear_textbox(self):

        if not self.stop_event.is_set():

            pygame.mixer.music.stop()
            
            self.result_textbox.configure(state="normal")
            self.result_textbox.delete("1.0", "end")
            self.result_textbox.configure(state="disabled")
            
            self.drop_label.configure(text=self.upload_label + ".")
            self.drop_label.place(relx=0.5, rely=0.5, anchor="center")
            
            self.is_running = False

    def informations(self, function):

        if self.is_running:

            return

        generator = function()

        if generator is None:
            
            return

        self.ask_duration()

        def task():

            try:

                self.is_running = True

                self.play_music()

                self.pyforensic.after(0, self.drop_label.place_forget)       
                self.update_result("", True)

                for output in generator:

                    if self.stop_event.is_set():
                        
                        break

                    self.update_result(str(output), False)

            except Exception:

                self.update_result("An error occurred while displaying the plugin result !", False)

            finally:

                if not self.stop_event.is_set():

                    self.pyforensic.after(self.display_duration, self.clear_textbox)
                
                else:
                    
                    self.is_running = False

        self.pyforensic.after(3000, lambda: threading.Thread(target=task, daemon=True).start())

    def binary_analysis(self):

        if self.is_running:
            
            return

        if all([self.result_textbox.get("1.0", "end-1c").strip(), not self.drop_label.winfo_viewable()]):

            pygame.mixer.music.stop()
            
            self.result_textbox.configure(state="normal")
            self.result_textbox.delete("1.0", "end")
            self.result_textbox.configure(state="disabled")

            self.drop_label.configure(text=self.upload_label + ".")
            self.drop_label.place(relx=0.5, rely=0.5, anchor="center")

            if hasattr(self, "path"):
                
                del self.path

            return

        elif hasattr(self, "path") and self.path.is_dir():

            self.ask_duration()

            def run_analysis():
                
                try:

                    self.is_running = True

                    self.play_music()
                    
                    self.pyforensic.after(0, self.drop_label.place_forget)

                    for result_data in Analyze().analyze(self.path):

                        if self.stop_event.is_set():

                            break

                        self.update_result(str(result_data), False)

                except Exception:

                    self.update_result("An error occurred while displaying the plugin result !", False)

                finally:

                    if not self.stop_event.is_set():

                        self.pyforensic.after(self.display_duration, self.clear_textbox)
                    
                    else:
                        
                        self.is_running = False

            self.pyforensic.after(3000, lambda: threading.Thread(target=run_analysis, daemon=True).start())

        else:

            self.result_textbox.configure(state="normal")
            self.result_textbox.delete("1.0", "end")
            self.result_textbox.configure(state="disabled")
            
            self.drop_label.configure(text=self.upload_label + " !")
            self.drop_label.place(relx=0.5, rely=0.5, anchor="center")

if __name__ == "__main__":

    try:

        internet = requests.get("https://google.com", timeout=5)

        if internet.status_code == 200:

            PyForensic()

    except requests.exceptions.ConnectionError:

        showwarning(title="PyForensic :", message="To use PyForensic, please connect to a network with Internet access !")