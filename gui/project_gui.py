from tkinter import *
from tkinter import ttk
from typing import Tuple

from PIL import ImageTk, Image
from encrypting.users import Users
import subprocess
import re
from mitm.final_run import FinalRun

CMDIP_REGEX = "\s((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\s"
SUBNET_REG = "Subnet\sMask\s[\.|\s]+:\s((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
GATEWAY_REG = "Default\sGateway\s[\.|\s]+:\s((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
GATEWAYIP = ''
IP_LIST = []
VICTIM_IP = ''

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
    del final_list[0]
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
        self.var = IntVar()
        self.var.set(1)
        self.read_b = Radiobutton(self.root, text="Read data", font=("Clibri", 20), variable=self.var, value=1)
        self.change_b = Radiobutton(self.root, text="Edit data", font=("Clibri", 20), variable=self.var, value=2)


    def check_validation(self, pw, un):
        #TODO: block weak passwords and username (8 chars min, several characters etc.)
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
        global VICTIM_IP
        VICTIM_IP = str(self.victimip_entry.get())
        print("vip: " + str(VICTIM_IP))
        gwip = str(self.gatewayip_entry.get())
        print(str(gwip) + str(VICTIM_IP))
        print(str(self.is_ip(VICTIM_IP)) + str(self.is_ip(gwip)) + str(self.is_in_list(VICTIM_IP, IP_LIST)) + str(gwip == GATEWAYIP))
        if self.is_ip(VICTIM_IP) and self.is_ip(gwip) and self.is_in_list(VICTIM_IP, IP_LIST) and gwip == GATEWAYIP:
            self.action_screen()
        else:
            self.lable5 = Label(self.root, text="Invalid input.", font=("Clibri", 20), bg=BG_COLOR1)
            self.lable5.place(relx=0.1, rely=0.4, anchor="nw")

    def choose_action(self, value):
        if value == 1:
            self.read_screen()
        elif value == 2:
            self.edit_screen()

    def action_screen(self):
        self.lable5.destroy()
        self.lable1.destroy()
        self.lable2.destroy()
        self.lable3.destroy()
        self.lable4.destroy()
        self.victimip_entry.destroy()
        self.gatewayip_entry.destroy()
        self.start_btn.destroy()

        self.read_b = Radiobutton(self.root, text="Read data", font=("Clibri", 20), variable=self.var, value=1, bg=BG_COLOR1)
        self.change_b = Radiobutton(self.root, text="Edit data", font=("Clibri", 20), variable=self.var, value=2, bg=BG_COLOR1)

        self.start_btn = Button(self.root, text="start", font=("Clibri", 18), width=5, fg="black", bg="white",
                                command=lambda: self.choose_action(self.var.get()))

        self.lable1 = Label(self.root, text="What would you like to do?", font=("Clibri", 20),
                            bg=BG_COLOR1)

        self.lable1.place(relx=0.3, rely=0.1, anchor="nw")
        self.read_b.place(relx=0.40, rely=0.3, anchor="nw")
        self.change_b.place(relx=0.4, rely=0.5, anchor="nw")
        self.start_btn.place(relx=0.42, rely=0.8, anchor="nw")

    def read_screen(self):
        self.root.geometry("1000x500+290+150")
        self.lable1.destroy()
        self.read_b.destroy()
        self.change_b.destroy()
        self.start_btn.destroy()
        self.root.configure(bg="#75BFD7")

        style = ttk.Style()
        style.theme_use('default')
        style.configure("Treeview", background="D3D3D3", foreground="white", rowheight=25, fieldbackground= "D3D3D3")
        style.map("Treeview", background=[('selected', "#347083")])

        tree_frame = Frame(self.root)
        tree_frame.pack(pady=10)
        tree_scroll = Scrollbar(tree_frame)
        tree_scroll.pack(side=RIGHT, fill=Y)

        self.my_tree = ttk.Treeview(tree_frame, yscrollcommand=tree_scroll.set, selectmode= "extended")
        self.my_tree.pack()

        tree_scroll.config(command= self.my_tree.yview())

        self.my_tree['columns'] = ("packet id", "src ip", "dst ip", "request type", "request parameters", "data", "src port"
                              , "dst port")
        self.my_tree.column("#0", width=0, stretch=NO)
        self.my_tree.column("packet id", anchor=CENTER, width=100)
        self.my_tree.column("src ip", anchor=W, width=120)
        self.my_tree.column("dst ip", anchor=W, width=120)
        self.my_tree.column("request type", anchor=W, width=120)
        self.my_tree.column("request parameters", anchor=W, width=120)
        self.my_tree.column("data", anchor=W, width=120)
        self.my_tree.column("src port", anchor=W, width=120)
        self.my_tree.column("dst port", anchor=W, width=120)

        self.my_tree.heading("#0", text="", anchor=W)
        self.my_tree.heading("packet id", text="packet id", anchor=CENTER)
        self.my_tree.heading("src ip", text="src ip", anchor=W)
        self.my_tree.heading("dst ip", text="dst ip", anchor=W)
        self.my_tree.heading("request type", text="request type", anchor=W)
        self.my_tree.heading("request parameters", text="request parameters", anchor=W)
        self.my_tree.heading("data", text="data", anchor=W)
        self.my_tree.heading("src port", text="src port", anchor=W)
        self.my_tree.heading("dst port", text="dst port", anchor=W)

        self.my_tree.tag_configure('oddrow', background="white")
        self.my_tree.tag_configure('evenrow', background="lightblue")

        self.data_frame = LabelFrame(self.root, text = "packet information", fg="black", bg="#75BFD7")
        self.data_frame.pack(fill="x", expand="yes", padx=20)

        id_lable = Label(self.data_frame, text="Packet ID", bg="#75BFD7")
        id_lable.grid(row=0, column=0, padx=10, pady=10)
        id_entry = Entry(self.data_frame)
        id_entry.grid(row=0, column=1, padx=10, pady=10)

        srcip_lable = Label(self.data_frame, text="Src ip",bg="#75BFD7")
        srcip_lable.grid(row=0, column=2, padx=10, pady=10)
        srcip_entry = Entry(self.data_frame)
        srcip_entry.grid(row=0, column=3, padx=10, pady=10)

        dstip_lable = Label(self.data_frame, text="Dst ip", bg="#75BFD7")
        dstip_lable.grid(row=0, column=4, padx=10, pady=10)
        dstip_entry = Entry(self.data_frame)
        dstip_entry.grid(row=0, column=5, padx=10, pady=10)

        rt_lable = Label(self.data_frame, text="Request type", bg="#75BFD7")
        rt_lable.grid(row=0, column=6, padx=10, pady=10)
        rt_entry = Entry(self.data_frame)
        rt_entry.grid(row=0, column=7, padx=10, pady=10)

        rp_lable = Label(self.data_frame, text="Request parameters", bg="#75BFD7")
        rp_lable.grid(row=1, column=0, padx=10, pady=10)
        rp_entry = Entry(self.data_frame)
        rp_entry.grid(row=1, column=1, padx=10, pady=10)

        data_lable = Label(self.data_frame, text="data", bg="#75BFD7")
        data_lable.grid(row=1, column=2, padx=10, pady=10)
        data_entry = Entry(self.data_frame)
        data_entry.grid(row=1, column=3, padx=10, pady=10)

        sp_lable = Label(self.data_frame, text="Src port", bg="#75BFD7")
        sp_lable.grid(row=1, column=4, padx=10, pady=10)
        sp_entry = Entry(self.data_frame)
        sp_entry.grid(row=1, column=5, padx=10, pady=10)

        dp_lable = Label(self.data_frame, text="Dst port", bg="#75BFD7")
        dp_lable.grid(row=1, column=6, padx=10, pady=10)
        dp_entry = Entry(self.data_frame)
        dp_entry.grid(row=1, column=7, padx=10, pady=10)

        self.button_frame = LabelFrame(self.root, text="Commands", bg="#75BFD7")
        self.button_frame.pack(fill="x", expand="yes", padx=20)

        update_button = Button(self.button_frame, text="continue",bg="#67A6BB")
        update_button.grid(row=0, column=1, padx=10, pady=10)

        stop_button = Button(self.button_frame, text="pause sennding packets", bg="#67A6BB")
        stop_button.grid(row=0, column=0, padx=10, pady=10)

        restore_button = Button(self.button_frame, text="stop attack", bg="#67A6BB")
        restore_button.grid(row=0, column=2, padx=10, pady=10)

        self.count = 0
        print("real vip" + str(VICTIM_IP))
        attacker = FinalRun(VICTIM_IP,GATEWAYIP, self.insert_to_table)
        attacker.start()

    def insert_to_table(self, info: Tuple[str, Tuple[str, ...]]):
        if self.count % 2 == 0:
            self.my_tree.insert(parent='', index='end', iid=self.count, text='', values=info[1], tags=('evenrow',))
        else:
            self.my_tree.insert(parent='', index='end', iid=self.count, text='', values=info[1], tags=('oddrow',))
        self.count += 1


    def edit_screen(self):
        self.lable1.destroy()
        self.read_b.destroy()
        self.change_b.destroy()
        self.start_btn.destroy()
        self.root.configure(bg="white")


        #attack = FinalRun(VICTIM_IP, GATEWAYIP)
        #attack.start()



if __name__ == '__main__':
    x = ProjectGui()
    x.login_registry_screen()
