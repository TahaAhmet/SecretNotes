import base64
from tkinter import *
from PIL import ImageTk, Image
from tkinter import messagebox
from cryptography.fernet import Fernet

window = Tk()
window.title("Secret Notes")
window.minsize(width=450, height=600)
window.config(padx=10, pady=10)

image_path = r"C:\Users\msi\PycharmProjects\SecretNotes\secret.jpg"

image = Image.open(image_path)
image = image.resize((200, 150))
image = ImageTk.PhotoImage(image)

image_label = Label(window, image=image)
image_label.pack(padx=5, pady=5)

title_label = Label(text="Enter your title")
title_label.pack()

title_entry = Entry(width=35)
title_entry.pack()

secret_label = Label(text="Enter your secret")
secret_label.pack()

secret_text = Text(width=36, height=10)
secret_text.pack()

master_key_label = Label(text="Enter master key")
master_key_label.pack()

master_key_entry = Entry(width=35, show="*")  # We added * because we want to hide Master Key.
master_key_entry.pack()


def generate_key(password):
    # Fernet key is must be 32 byte length. Therefore, we are using hash for generating key.
    password_hash = base64.urlsafe_b64encode(hash(password).to_bytes(32, byteorder='big'))
    return password_hash


def create_cipher(key):
    return Fernet(key)


def save_and_encrypt():
    title = title_entry.get()
    message = secret_text.get("1.0", "end-1c")
    master_secret = master_key_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        key = generate_key(master_secret)
        cipher = create_cipher(key)
        encrypted_message = cipher.encrypt(message.encode())

        try:
            with open("mysecret.txt", "ab") as data_file:
                data_file.write(f'\n{title}\n'.encode() + encrypted_message + b'\n')
        except Exception as e:
            messagebox.showinfo(title="Error!", message=f"Error while saving: {e}")

        finally:
            title_entry.delete(0, "end")
            master_key_entry.delete(0, "end")
            secret_text.delete("1.0", "end")


def decrypt():
    message_encrypted = secret_text.get("1.0", "end-1c")
    master_secret = master_key_entry.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            key = generate_key(master_secret)
            cipher = create_cipher(key)
            decrypted_message = cipher.decrypt(message_encrypted.encode()).decode()

            secret_text.delete("1.0", "end")
            secret_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")


save_encrypt_button = Button(text="Save & Encrypt", command=save_and_encrypt)
save_encrypt_button.pack(padx=3, pady=3)

save_decrypt_button = Button(text="Decrypt", command=decrypt)
save_decrypt_button.pack(padx=3, pady=3)

window.mainloop()

