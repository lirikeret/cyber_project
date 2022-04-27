from tkinter import *
from PIL import ImageTk, Image
from encrypting.users import Users
import subprocess
import re

CMDIP_REGEX = "\s((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\s"
SUBNET_REG = "Subnet\sMask\s[\.|\s]+:\s((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
GATEWAY_REG = "Default\sGateway\s[\.|\s]+:\s((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
GATEWAYIP = ''
IP_LIST = []

def find_mask():
    text = str(subprocess.check_output("cmd /c ipconfig", stderr=subprocess.STDOUT, shell=True))
    subnet_mask = re.search(SUBNET_REG, text).group(1)
    gateway = re.search(GATEWAY_REG, text).group(1)
    subsplit = subnet_mask.split(".")
    gatesplit = gateway.split(".")
    check_ip = []
    for i in range(0,4):
        if subsplit[i] == "255":
            check_ip.append(gatesplit[i])
    return check_ip, gateway

def clean_ip_list(ips, mask):
    final_list = []
    for ip in ips:
        x = ip.split(".")
        flag = True
        for i in range(0,len(mask)):
            if x[i] != mask[i]:
                flag = False
        if flag:
            final_list.append(".".join(x))
    return final_list

def avalable_ip_adresses():
    global IP_LIST, GATEWAYIP
    ip_addresses = str(subprocess.check_output("cmd /c arp -a", stderr=subprocess.STDOUT, shell=True))
    IP_LIST = re.findall(CMDIP_REGEX, ip_addresses)
    ip_subnet, GATEWAYIP = find_mask()
    IP_LIST.remove(GATEWAYIP)
    IP_LIST = clean_ip_list(IP_LIST, ip_subnet)
    IP_LIST.insert(0, "Available ip addresses")
    IP_LIST.append("\ngateway ip: \n" + str(GATEWAYIP))
    return "\n".join(IP_LIST)

INVALID_LIST = ["'", "username", "password"]
BG_COLOR1 = "#4275A8"
IP_REGEX = "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
AVAILABLE_IPS = avalable_ip_adresses()


class ProjectGui:
    def __init__(self):
        self.root = Tk()
        self.my_canvas = Canvas(self.root, width=485, height=355, bd=0, highlightthickness=0)
        self.reg_button = Button(self.root, text="registry", font=("Clibri", 14), width=7, fg="black", bg="#b29b8f")
        self.log_button = Button(self.root, text="login", font=("Clibri", 14), width=7, fg="black", bg="#b29b8f",
                                 command=self.login_screen)
        self.back_button = Button(self.root, text="back", font=("Clibri", 10), width=5, fg="white", bg="#2a3e5a",
                                  command=self.login_registry_screen)
        self.un_entry = Entry(self.root, font=("Clibri", 18), width=14, fg="black", bg="white", bd=0)
        self.pw_entry = Entry(self.root, font=("Clibri", 18), width=14, fg="black", bg="white", bd=0)
        self.users = Users()
        self.login_btn = Button(self.root, text="login", font=("Clibri", 12), width=7, fg="white", bg="#42536e",
                                command=self.handle_info)
        self.textid = 0
        self.start_btn = Button(self.root, text="start", font=("Clibri", 10), width=5, fg="white", bg="white",
                                command=self.check_input)
        self.victimip_entry = Entry(self.root, font=("Clibri", 18), width=14, fg="black", bg="white", bd=0)
        self.gatewayip_entry = Entry(self.root, font=("Clibri", 18), width=14, fg="black", bg="white", bd=0)
        self.lable1 = Label(self.root, text="Invalid input.", font=("Clibri", 20), bg=BG_COLOR1)
        self.lable2 = Label(self.root, text="Invalid input.", font=("Clibri", 20), bg=BG_COLOR1)
        self.lable3 = Label(self.root, text="Invalid input.", font=("Clibri", 20), bg=BG_COLOR1)
        self.lable4 = Label(self.root, text="Invalid input.", font=("Clibri", 20), bg=BG_COLOR1)
        self.lable5 = Label(self.root, text="Invalid input.", font=("Clibri", 20), bg=BG_COLOR1)

    def check_validation(self, pw, un):
        for i in INVALID_LIST:
            if i in pw or i in un:
                return False
        return True

    def resizer(self, e, canvas):
        global bg1, resized_bg, new_bg
        bg1 = Image.open(r"C:\Cyber\hacker2.webp")
        resized_bg = bg1.resize((e.width, e.height), Image.ANTIALIAS)
        new_bg = ImageTk.PhotoImage(resized_bg)
        canvas.create_image(0, 0, image=new_bg, anchor="nw")

    def login_registry_screen(self):
        self.my_canvas.destroy()

        self.root.geometry("485x355+480+200")
        self.root.title("MITM entry screen")
        icon = PhotoImage(file=r"C:\Users\lirik\Downloads\icon.png")
        self.root.iconphoto(False, icon)
        self.root.resizable(height=False, width=False)

        bg = ImageTk.PhotoImage(file=r"C:\Cyber\hacker2.webp")

        self.my_canvas = Canvas(self.root, width=485, height=355, bd=0, highlightthickness=0)
        self.my_canvas.pack(fill="both", expand=True)
        self.my_canvas.create_image(0, 0, image=bg, anchor="nw")

        self.reg_button = Button(self.root, text="registry", font=("Clibri", 14), width=7, fg="black", bg="#b29b8f",
                                 command=self.reg_screen)
        self.log_button = Button(self.root, text="login", font=("Clibri", 14), width=7, fg="black", bg="#b29b8f",
                                 command=self.login_screen)

        reg_button_window = self.my_canvas.create_window(195, 300, anchor="nw", window=self.reg_button)
        log_button_window = self.my_canvas.create_window(195, 250, anchor="nw", window=self.log_button)

        # root.bind('<Configure>', lambda x: resizer(x, my_canvas))

        self.root.mainloop()

    def entry_clear(self, e):
        if self.un_entry.get() == "username" or self.pw_entry.get() == "password":
            self.un_entry.delete(0, END)
            self.pw_entry.delete(0, END)
            self.pw_entry.config(show="*")

    def login_screen(self):
        self.reg_button.destroy()
        self.log_button.destroy()

        self.root.title("MITM login screen")

        self.un_entry = Entry(self.root, font=("Clibri", 18), width=14, fg="black", bg="white", bd=0)
        self.pw_entry = Entry(self.root, font=("Clibri", 18), width=14, fg="black", bg="white", bd=0)

        self.un_entry.insert(0, "username")
        self.pw_entry.insert(0, "password")

        un_window = self.my_canvas.create_window(145, 240, anchor="nw", window=self.un_entry)
        pw_window = self.my_canvas.create_window(145, 290, anchor="nw", window=self.pw_entry)

        self.un_entry.bind("<Button-1>", self.entry_clear)
        self.pw_entry.bind("<Button-1>", self.entry_clear)

        self.login_btn = Button(self.root, text="login", font=("Clibri", 12), width=7, fg="white", bg="#42536e",
                                command=self.handle_info)
        self.back_button = Button(self.root, text="back", font=("Clibri", 10), width=5, fg="white", bg="#2a3e5a",
                                  command=self.login_registry_screen)

        log_button_window = self.my_canvas.create_window(380, 292, anchor="nw", window=self.login_btn)
        back_button_window = self.my_canvas.create_window(10, 10, anchor="nw", window=self.back_button)

    def handle_info(self):
        pw = str(self.pw_entry.get())
        un = str(self.un_entry.get())
        valid = self.check_validation(pw, un)
        if valid:
            ans = self.users.check_user(un, pw)
            if ans:
                self.main_screen()
            elif not ans:
                self.my_canvas.delete(self.textid)
                self.textid = self.my_canvas.create_text(90, 100, text="Username or password are incorrect.",
                                                         font=("Clibri bald", 12),
                                                         fill="white", width=160)
                # wrong password
        else:
            self.my_canvas.delete(self.textid)
            self.textid = self.my_canvas.create_text(90, 100, text="Invalid input", font=("Clibri bald", 12),
                                                     fill="white", width=160)

    def reg_screen(self):
        """
        pwhen finidhed, sent to confirmation screen
        :return:
        """
        self.reg_button.destroy()
        self.log_button.destroy()

        self.root.title("MITM registry screen")

        self.un_entry = Entry(self.root, font=("Clibri", 18), width=14, fg="black", bg="white", bd=0)
        self.pw_entry = Entry(self.root, font=("Clibri", 18), width=14, fg="black", bg="white", bd=0)

        self.un_entry.insert(0, "username")
        self.pw_entry.insert(0, "password")

        un_window = self.my_canvas.create_window(145, 240, anchor="nw", window=self.un_entry)
        pw_window = self.my_canvas.create_window(145, 290, anchor="nw", window=self.pw_entry)

        self.un_entry.bind("<Button-1>", self.entry_clear)
        self.pw_entry.bind("<Button-1>", self.entry_clear)

        self.log_button = Button(self.root, text="register", font=("Clibri", 12), width=7, fg="white", bg="#42536e",
                                 command=self.conf_screen)
        self.back_button = Button(self.root, text="back", font=("Clibri", 10), width=5, fg="white", bg="#2a3e5a",
                                  command=self.login_registry_screen)

        log_button_window = self.my_canvas.create_window(380, 292, anchor="nw", window=self.log_button)
        back_button_window = self.my_canvas.create_window(10, 10, anchor="nw", window=self.back_button)

        self.textid = self.my_canvas.create_text(90, 100,
                                                 text="Welcome! please enter your desiered username and password. "
                                                      "After the registry, log in.", font=("Clibri bald", 12),
                                                 fill="white",
                                                 width=160)

    def conf_screen(self):
        pw = str(self.pw_entry.get())
        un = str(self.un_entry.get())
        if self.users.insert_user(un, pw) == "exists":
            self.my_canvas.delete(self.textid)
            self.textid = self.my_canvas.create_text(90, 100, text="User already exists.", font=("Clibri bald", 12),
                                                     fill="white", width=160)
        else:
            self.my_canvas.delete(self.textid)
            self.un_entry.destroy()
            self.pw_entry.destroy()
            self.log_button.destroy()
            self.my_canvas.create_text(90, 100, text="Registry completed successfully! go back and log in. ",
                                       font=("Clibri bald", 12), fill="white", width=160)

    def main_screen(self):
        self.my_canvas.destroy()

        self.root.geometry("900x500+290+150")
        self.root.title("MITM main screen")
        self.root.configure(bg=BG_COLOR1)
        icon = PhotoImage(file=r"C:\Users\lirik\Downloads\icon.png")
        self.root.iconphoto(False, icon)
        # self.root.resizable(height=True, width=True)

        self.start_btn = Button(self.root, text="start", font=("Clibri", 18), width=5, fg="black", bg="white",
                                command=self.check_input)

        self.start_btn.pack()
        self.start_btn.place(relx=0.45, rely=0.8, anchor="nw")

        self.victimip_entry = Entry(self.root, font=("Clibri", 20), width=14, fg="black", bg="white", bd=0)
        self.gatewayip_entry = Entry(self.root, font=("Clibri", 20), width=14, fg="black", bg="white", bd=0)

        self.victimip_entry.pack()
        self.gatewayip_entry.pack()
        self.victimip_entry.place(relx=0.45, rely=0.3, anchor="nw")
        self.gatewayip_entry.place(relx=0.45, rely=0.5, anchor="nw")

        self.lable1 = Label(self.root, text="Please enter victim's ip and gateway ip", font=("Clibri", 20),
                            bg=BG_COLOR1)
        self.lable2 = Label(self.root, text="Victim ip", font=("Clibri", 20), bg=BG_COLOR1)
        self.lable3 = Label(self.root, text="Gateway ip", font=("Clibri", 20), bg=BG_COLOR1)
        self.lable4 = Label(self.root, text=AVAILABLE_IPS, font=("Clibri", 12), bg=BG_COLOR1)

        self.lable2.place(relx=0.25, rely=0.3, anchor="nw")
        self.lable3.place(relx=0.25, rely=0.5, anchor="nw")
        self.lable1.place(relx=0.23, rely=0.1, anchor="nw")
        self.lable4.place(relx=0.78, rely=0.18, anchor="nw")

    def is_ip(self, addr):
        if re.search(IP_REGEX, addr):
            return True
        else:
            return False

    def is_in_list(self, ip, lst):
        for i in lst:
            print(i)
            if ip == i:
                return True
        return False

    def check_input(self):
        vmip = str(self.victimip_entry.get())
        gwip = str(self.gatewayip_entry.get())
        print(str(gwip) + str(vmip))
        print(str(self.is_ip(vmip)) + str(self.is_ip(gwip)) + str(self.is_in_list(vmip, IP_LIST)) + str(gwip == GATEWAYIP))
        if self.is_ip(vmip) and self.is_ip(gwip) and self.is_in_list(vmip, IP_LIST) and gwip == GATEWAYIP:
            self.info_screen()
        else:
            self.lable5 = Label(self.root, text="Invalid input.", font=("Clibri", 20), bg=BG_COLOR1)
            self.lable5.place(relx=0.1, rely=0.4, anchor="nw")

    def info_screen(self):
        self.lable5.destroy()
        self.lable1.destroy()
        self.lable2.destroy()
        self.lable3.destroy()
        self.lable4.destroy()
        self.victimip_entry.destroy()
        self.gatewayip_entry.destroy()
        self.start_btn.destroy()


if __name__ == '__main__':
    x = ProjectGui()
    x.login_registry_screen()
