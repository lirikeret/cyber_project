from tkinter import *
from PIL import ImageTk, Image
from encrypting.users import Users


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
        self.login_btn = Button(self.root, text="login", font=("Clibri", 12), width=7, fg="white", bg="#42536e", command=self.handle_info)
        self.textid=0

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

        self.login_btn = Button(self.root, text="login", font=("Clibri", 12), width=7, fg="white", bg="#42536e", command=self.handle_info)
        self.back_button = Button(self.root, text="back", font=("Clibri", 10), width=5, fg="white", bg="#2a3e5a",
                                  command=self.login_registry_screen)

        log_button_window = self.my_canvas.create_window(380, 292, anchor="nw", window=self.login_btn)
        back_button_window = self.my_canvas.create_window(10, 10, anchor="nw", window=self.back_button)

    def handle_info(self):
        pw = str(self.pw_entry.get())
        un = str(self.un_entry.get())
        ans = self.users.check_user(un, pw)
        if ans == "create user":
            self.my_canvas.create_text(90, 100, text="User doesn't exists.", font=("Clibri bald", 12),
                                      fill="white", width=160)
            # user doesnt exists
        elif ans == True:
            self.main_screen()
        elif ans == False:
            self.my_canvas.create_text(90, 100, text="Invalid password. Please try again.", font=("Clibri bald", 12),
                                       fill="white", width=160)
            # wrong password

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

        self.log_button = Button(self.root, text="register", font=("Clibri", 12), width=7, fg="white", bg="#42536e", command= self.conf_screen)
        self.back_button = Button(self.root, text="back", font=("Clibri", 10), width=5, fg="white", bg="#2a3e5a",
                                  command=self.login_registry_screen)

        log_button_window = self.my_canvas.create_window(380, 292, anchor="nw", window=self.log_button)
        back_button_window = self.my_canvas.create_window(10, 10, anchor="nw", window=self.back_button)

        self.textid = self.my_canvas.create_text(90, 100, text="Welcome! please enter your desiered username and password. "
                                                 "After the registry, log in.", font=("Clibri bald", 12), fill="white",
                                   width=160)

    def conf_screen(self):
        pw = str(self.pw_entry.get())
        un = str(self.un_entry.get())
        if self.users.insert_user(un,pw) == "exists":
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
        icon = PhotoImage(file=r"C:\Users\lirik\Downloads\icon.png")
        self.root.iconphoto(False, icon)
        self.root.resizable(height=True, width=True)

        


if __name__ == '__main__':
    x = ProjectGui()
    x.login_registry_screen()
