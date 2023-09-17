from tkinter import *
from tkinter import messagebox
import base64
###################################
# Crypt base64 Func
###################################
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

###################################
# Save Notes Func
###################################
def save_and_encrypt_notes():
    title = title_entry.get()
    message = secret_text.get("1.0", END)
    master_key = key_entry.get()
    if len(title) == 0 or len(message) == 0 or len(master_key) == 0:
        messagebox.showwarning(title="ERROR!", message="Please Enter All Information.")
    else:
        message_encrypted = encode(master_key, message)

        try:
            with open("mysecretnotes.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecretnotes.txt", "w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            title_entry.delete(0, END)
            key_entry.delete(0, END)
            secret_text.delete("1.0", END)

###################################
# Decrypt Notes
###################################
def decrypt_notes():
    message_encrypt = secret_text.get("1.0", END)
    message_key = key_entry.get()

    if len(message_encrypt) == 0 or len(message_key) == 0:
        messagebox.showinfo(title="ERROR!", message="Please Enter All Information!")
    else:
        try:
            decrypted_message = decode(message_key, message_encrypt)
            secret_text.delete("1.0", END)
            secret_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="ERROR!", message="Please Make Sure of Encrypted Info")

###################################
# UI
###################################
window = Tk()

window_height = 750
window_width = 400

screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()

x_cordinate = int((screen_width/2) - (window_width/2))
y_cordinate = int((screen_height/2) - (window_height/2))

window.geometry("{}x{}+{}+{}".format(window_width, window_height, x_cordinate, y_cordinate))

window.title("Secret Notes")
window.config(padx=30, pady=30)

###################################
# Logo
###################################
icon = PhotoImage(file= "top_secret.png")
icon_label = Label(window, image=icon)
icon_label.pack()

###################################
# Tıtle Label and Tıtle Entry
###################################
title_label = Label(window, text="ENTER YOUR TITLE", font=("Helvetica",18,"normal"))
title_label.pack()

title_entry = Entry(window, width=38)
title_entry.pack()

###################################
# Secret Label and Secret Text
###################################
secret_label = Label(window, text="ENTER YOUR SECRET NOTE", font=("Helvetica", 18, "normal"))
secret_label.pack()

secret_text = Text(window, width=50, height=30)
secret_text.pack()

###################################
# Key Label and Key Entry
###################################
key_label = Label(window, text="ENTER MASTER KEY", font=("Helvetica", 18, "normal"))
key_label.pack()

key_entry = Entry(window, width=38)
key_entry.pack()

###################################
# Save & Encrypt - Decrypt Button
###################################
save_encrypt_button = Button(window, text="Save & Encrypt", width=35, command=save_and_encrypt_notes)
save_encrypt_button.pack()

decrypt_button = Button(window, text="Decrypt", width=35, command=decrypt_notes)
decrypt_button.pack()

window.mainloop()