#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pymongo
from pymongo import MongoClient
import hashlib
import os
import random
import string
import requests
import pyperclip
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from difflib import SequenceMatcher
import tkinter
from tkinter import *
from tkinter import font
from tkinter import ttk


# In[2]:


# Session vars #
################
global s_uname
global s_mp
global s_salt
s_uname = ""
s_mp = ""
s_salt = ""


# In[3]:


# Logout Sript #
################
def logout():
    s_uname = ""
    s_mp = ""
    s_salt = ""
    for record in search_tree.get_children():
        search_tree.delete(record)
    loginPopup()


# In[4]:


# Mongo Connection #
###################
cluster = MongoClient("mongodb://username:password@10.10.10.10:27098/passkeep?authSource=passkeep")
db = cluster["passkeep"]
users_collection = db["passkeep_users"]


# In[5]:


# Similarity calculation function #
###################################
def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()


# In[6]:


# Search function
def searchPassword(event=None):
    
    name = search_value.get()
    
    count = 0
    
    cleanTree()
    
    results = password_database.find({})
        
    for row in results:
        
        database_alias = row['name']
        
        if similar(name, database_alias) > 0.4 or name in database_alias:
                        
            url_hash = row['url']
            username_hash = row['username']
            password_hash = row['password']

            master_pass = s_mp.encode()  # Convert to type bytes
            salt = url_hash[:16]

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_pass))  # Can only use kdf once
            cipher_suite = Fernet(key)

            url_plain = cipher_suite.decrypt(url_hash[16:]).decode('ascii')
            username_plain = cipher_suite.decrypt(username_hash).decode('ascii')
            password_plain = cipher_suite.decrypt(password_hash).decode('ascii')

            search_tree.insert(parent='', index='0', iid=count, text=password_plain, values=(row['name'], url_plain, username_plain, '***************'))
            count += 1
    
    if name == "":
        pass
    else:
        search_tree.focus(0)
        search_tree.selection_set(0)


# In[7]:


# Clear button
def clearButton():
    search_entry.delete(0, END)
    cleanTree()
    getPasswords()


# In[8]:


# Copy Functions #
##################

# Copy URL
def cpURL():
    try:
        currentItem = search_tree.focus()
        item = search_tree.item(currentItem)
        values = item['values']
        pyperclip.copy(values[1])
    except IndexError as e:
        pass
    
# Copy Username
def cpUsername():
    try:
        currentItem = search_tree.focus()
        item = search_tree.item(currentItem)
        values = item['values']
        pyperclip.copy(values[2])
    except IndexError as e:
        pass

# Copy Password
def cpPassword():
    try:
        currentItem = search_tree.focus()
        item = search_tree.item(currentItem)
        values = item['values']
        if item['text'] != "***************":
            pyperclip.copy(item['text'])
        else:
            pyperclip.copy(values[3])
    except IndexError as e:
        pass


# In[9]:


# Show Password
def showPassword(a):
    try:
        currentItem = search_tree.focus()
        item = search_tree.item(currentItem)
        values = item['values']
        search_tree.item(currentItem, text=values[3], values=(values[0], values[1], values[2], item['text']))
    except IndexError as e:
        pass


# In[10]:


def cleanTree():
    for record in search_tree.get_children():
        search_tree.delete(record)


# In[11]:


# Remove Password
def removeSelected():
    try:
        currentItem = search_tree.selection()[0]
        item = search_tree.item(currentItem)
        values = item['values']
        password_database.delete_one( { 'name': values[0] } )
        search_tree.delete(currentItem)
        remove_popup.destroy()

    except IndexError as e:
        remove_popup.destroy()
        
# Confirm removal
def confirmRemove():
    global remove_popup
    remove_popup = Frame(mainCanvas, bd=0, relief=RAISED)
    remove_popup.place(rely=0.92, relx=0.8, anchor=S, width=275, height=130)
    
#     Are you sure label
    confirm_label = Label(remove_popup, text="Are you sure?")
    confirm_label['font'] = subtitle
    confirm_label.pack(pady=10)
    
#     Yes and No buttons
    yes_button = Button(remove_popup, text="Yes", fg='red', width=2, height=2, command=removeSelected)
    yes_button.place(rely=0.6, relx=0.35, anchor='center')
    
    no_button = tkinter.Button(remove_popup, text="No", fg='green', width=3, height=3, command=remove_popup.destroy)
    no_button.place(rely=0.6, relx=0.65, anchor='center')


# In[12]:


# Show results #
################
def getPasswords():

    # Insert Data
    
    results = password_database.find({})
    
    count = 0
    
    for row in results:
        
#         Decrypt Data
        
        url_hash = row['url']
        username_hash = row['username']
        password_hash = row['password']
        
        master_pass = s_mp.encode()  # Convert to type bytes
        salt = url_hash[:16]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_pass))  # Can only use kdf once
        cipher_suite = Fernet(key)

        url_plain = cipher_suite.decrypt(url_hash[16:]).decode('ascii')
        username_plain = cipher_suite.decrypt(username_hash).decode('ascii')
        password_plain = cipher_suite.decrypt(password_hash).decode('ascii')
        
        search_tree.insert(parent='', index='0', iid=count, text=password_plain, values=(row['name'], url_plain, username_plain, '***************'))
        count += 1


# In[13]:


# Login user in #
#################
def login_user(event=None):
    
    username = username_login.get()
    password = pass_login.get()
    
    if(not username) or (not password):
        
        Label(login_popup, text="Empty fields. Please fill in all feilds!", fg="red", font=("calibri", 11)).place(rely=0.77, relx=0.5, anchor='center')
        
    else:
        
        results = users_collection.find({"username":username})
                
        for result in results:
            password_hash = result["password"]
            salt = password_hash[:27]
            key = hashlib.pbkdf2_hmac('md5', password.encode('utf-8'), salt, 100000)
            new_hash = salt + key
            
            if password_hash == new_hash:
                
                global s_uname
                global pwd
                global s_salt
                
                s_uname = (result["username"])
                s_mp = password
                s_salt = salt
                
#                 Set password database
                global password_database
                password_database = db[s_uname]
                
                login_canvas.destroy()
                search_entry.focus()
                getPasswords()
                
            else:
                Label(login_popup, text="Login credentials incorrect. Please try again!", fg="red", font=("calibri", 11)).place(rely=0.83, relx=0.5, anchor='center')


# In[14]:


# Register user to database #
#############################
def register_user(event=None):
    
#     Remove Previous output messages
    
    fname = fname_reg.get()
    lname = lname_reg.get()
    email = email_reg.get()
    username_send = username_reg.get()
    password1 = password1_reg.get()
    password2 = password2_reg.get()
    
    if(not fname) or (not lname) or (not email) or (not username_send) or (not password1) or (not password2):
        
#         Output empty fields error
        Label(register_popup, text="Empty fields. Please fill in all feilds!", fg="red", font=("calibri", 11)).place(rely=0.82, relx=0.5, anchor='center')
        
        
    else:
        
        usernameCheck = users_collection.find({"username":username_send})
        
        userCount = 0
        
        for row in usernameCheck:
            userCount += 1
        
        if userCount < 1:
        
            if password1 == password2:

                salt = os.urandom(27)
                key = hashlib.pbkdf2_hmac('md5', password1.encode('utf-8'), salt, 100000)

                password_hash = salt + key

                post = {"fname": fname, "lname": lname, "email": email, "username": username_send, "password":password_hash}
                users_collection.insert_one(post)

#                 Clear text fields
                fname_entry_reg.delete(0, END)
                lname_entry_reg.delete(0, END)
                email_entry_reg.delete(0, END)
                username_entry_reg.delete(0, END)
                pass1_entry_reg.delete(0, END)
                pass2_entry_reg.delete(0, END)


#                 Output success message
                Label(register_popup, text="Registration Successful!", fg="green", font=("calibri", 11)).place(rely=0.87, relx=0.5, anchor='center')

            else:
#                 Output passwords dont match error
                Label(register_popup, text="Passwords do not match. Please try again!", fg="red", font=("calibri", 11)).place(rely=0.86, relx=0.5, anchor='center')
        else:
            Label(register_popup, text="Username taken. Please try a different one!", fg="red", font=("calibri", 11)).place(rely=0.84, relx=0.5, anchor='center')


# In[15]:


# Generate Password function #
##############################
def generate_password():
    newpass = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation) for _ in range(20))
    pyperclip.copy(newpass)
    pass_box.delete(0,END)
    pass_box.insert(0,newpass)
    global output_add
    Label(add_popup, text="Password Copied to clipboard!", fg="green", font=("calibri", 11)).place(rely=0.78, relx=0.5, anchor='center')
    return


# In[16]:


# Save Password #
#################
def save_password():
        
    name_save = name_add.get()
    url_save = url_add.get()
    username_save = username_add.get()
    password_save = password_add.get()
    
    salt = os.urandom(16)
    master_pass = s_mp.encode()  # Convert to type bytes
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_pass))  # Can only use kdf once
    cipher_suite = Fernet(key)
    
    url_hash = salt + cipher_suite.encrypt(url_save.encode())
    username_hash = cipher_suite.encrypt(username_save.encode())
    password_hash = cipher_suite.encrypt(password_save.encode())
    
#     password_database = db[s_uname]
    post = {"name":name_save, "url":url_hash, "username":username_hash, "password":password_hash}
    password_database.insert_one(post)
        
#     Close add popup
    add_popup.destroy()
    
#     Clean results tree
    cleanTree()
    
#     Output Passwords
    getPasswords()


# In[17]:


root = Tk()
root.title("PassKeep")
root.geometry('1080x768+150+200')
root.minsize(640, 570)
mainCanvas = Canvas(root, highlightthickness=0)
mainCanvas.place(relwidth=1, relheight=1)

# Fonts
title = font.Font(family='Helvetica', size=30, weight='bold')
subtitle = font.Font(family="Helvetica", size=20)


# In[18]:


def registerPopup():
    global register_canvas
    register_canvas = Frame(mainCanvas)
    register_canvas.place(rely=0.5, relx=0.5, anchor='center', relwidth=1, relheight=1)
    global register_popup
    register_popup = Frame(register_canvas, bd=0, relief=RAISED)
    register_popup.place(relx=0.5, rely=0.5, anchor='center', width=300, height=600)
    
#     Required variables
    global fname_reg
    global lname_reg
    global email_reg
    global username_reg
    global password1_reg
    global password2_reg
    
    global fname_entry_reg
    global lname_entry_reg
    global email_entry_reg
    global username_entry_reg
    global pass1_entry_reg
    global pass2_entry_reg
    
    fname_reg = tkinter.StringVar()
    lname_reg = tkinter.StringVar()
    email_reg = tkinter.StringVar()
    username_reg = tkinter.StringVar()
    password1_reg = tkinter.StringVar()
    password2_reg = tkinter.StringVar()
    
#     Passkeep Title
    passkeep_title = Label(register_popup, text="PassKeep", height=1)
    passkeep_title['font'] = title
    passkeep_title.pack()
    
#     Register Title
    register_title = Label(register_popup, text="Register", height=2)
    register_title['font'] = subtitle
    register_title.pack()
    
#     First Name
    fname_label = Label(register_popup, text="First Name:", height=2)
    fname_entry_reg = Entry(register_popup, textvariable=fname_reg)
    fname_entry_reg.focus()
    fname_label.pack()
    fname_entry_reg.pack()
    
#     Last Name
    lname_label = Label(register_popup, text="Last Name:", height=2)
    lname_entry_reg = Entry(register_popup, textvariable=lname_reg)
    lname_label.pack()
    lname_entry_reg.pack()

#     Email
    email_label = Label(register_popup, text="Email:", height=2)
    email_entry_reg = Entry(register_popup, textvariable=email_reg)
    email_label.pack()
    email_entry_reg.pack()

#     Username
    username_label = Label(register_popup, text="Username:", height=2)
    username_entry_reg = Entry(register_popup, textvariable=username_reg)
    username_label.pack()
    username_entry_reg.pack()

#     Password1
    pass1_label = Label(register_popup, text="Master Password:", height=2)
    pass1_entry_reg = Entry(register_popup, show='*', textvariable=password1_reg)
    pass1_label.pack()
    pass1_entry_reg.pack()
    
#     Password2
    pass2_label = Label(register_popup, text="Confirm Master Password:", height=2)
    pass2_entry_reg = Entry(register_popup, show='*', textvariable=password2_reg)
    pass2_entry_reg.bind('<Return>', register_user)
    pass2_label.pack()
    pass2_entry_reg.pack()
    
#     Back
    back_button = Button(register_popup, text="Back", command=register_canvas.destroy)
    back_button.place(rely=0.9, relx=0.2)
    
#     Register Button
    register_button = Button(register_popup, text="Register", command=register_user)
    register_button.place(rely=0.9, relx=0.5)


# In[19]:


def loginPopup():
    global login_canvas
    login_canvas = Frame(mainCanvas)
    login_canvas.place(rely=0.5, relx=0.5, anchor='center', relwidth=1, relheight=1)
    global login_popup
    login_popup = Frame(login_canvas, bd=0, relief=RAISED)
    login_popup.place(relx=0.5, rely=0.5, anchor='center', width=300, height=350)
    
#     Required Vars
    global username_login
    global pass_login
    
    username_login = tkinter.StringVar()
    pass_login = tkinter.StringVar()
    
#     Login Content

#     Passkeep Title
    passkeep_title = Label(login_popup, text="PassKeep", height=1)
    passkeep_title['font'] = title
    passkeep_title.pack()
    
#     Login Title
    login_title = Label(login_popup, text="Login", height=2)
    login_title['font'] = subtitle
    login_title.pack()
    
    
#     Username/Email entry
    user_label = Label(login_popup, text="Username:", height=2)
    user_label.pack()
    
    global username_entry_login
    username_entry_login = Entry(login_popup, textvariable=username_login)
    username_entry_login.focus()
    username_entry_login.pack()
    
#     Password entry
    pass_label = Label(login_popup, text="Password:", height=2)
    pass_label.pack()
    
    pass_entry_log = Entry(login_popup, show='*', textvariable=pass_login)
    pass_entry_log.bind('<Return>', login_user)
    pass_entry_log.pack()
    
#     Login Button
    login_button = Button(login_popup, text="Login", command=login_user)
    login_button.pack()
    
#     Quit Button
    close_button = Button(login_popup, text="Quit", command=root.destroy)
    close_button.place(rely=0.9, relx=0.2)
    
#     Register Button
    register_button = Button(login_popup, text="Register", command=registerPopup)
    register_button.place(rely=0.9, relx=0.5)


# In[20]:


# Add popup
def addPopup(): 
    global add_popup
    add_popup = Frame(mainCanvas, bd=0, relief=RAISED)
    add_popup.place(rely=0.92, relx=0.6, anchor=S, width=275, height=450)
    
#     Required vars
    global url_add
    global username_add
    global password_add
    global name_add
    
    name_add = tkinter.StringVar()
    url_add = tkinter.StringVar()
    username_add = tkinter.StringVar()
    password_add = tkinter.StringVar()
    
#     Add Title and label
    passkeep_title = Label(add_popup, text="Add Password", height=2)
    passkeep_title['font'] = title
    passkeep_title.pack()
    
#     Name
    name_label = Label(add_popup, text="Website Name", height=2)
    name_label.pack()
    
    name_entry = Entry(add_popup, textvariable=name_add)
    name_entry.focus()
    name_entry.pack()

#     Url Entry
    url_label = Label(add_popup, text="URL", height=2)
    url_label.pack()
    
    url_entry = Entry(add_popup, textvariable=url_add)
    url_entry.pack()
    
#     Username Entry and label
    username_label = Label(add_popup, text="Username", height=2)
    username_label.pack()
    
    username_entry = Entry(add_popup, textvariable=username_add)
    username_entry.pack() 
    
#     Password Label
    password_label = Label(add_popup, text="Password", height=2)
    password_label.pack()
    
#     Generate Password button
    gen_pass_button = Button(add_popup, text="Gen", command=generate_password)
    gen_pass_button.pack()
    gen_pass_button.place(rely=0.69, relx=0.08)
    
#     Password output box
    global pass_box
    pass_box = Entry(add_popup, textvariable=password_add, justify=CENTER)
    pass_box.pack()
    pass_box.place(rely=0.69, relx=0.3, relwidth=0.6)
    
#     Save button
    save_button = Button(add_popup, text="Save", command=save_password)
    save_button.pack(side=BOTTOM)
    save_button.place(rely=0.85, relx=0.5, anchor='center')

#     Cancel button
    cancelbutton = Button(add_popup, text="Cancel", command=add_popup.destroy)
    cancelbutton.pack(side=BOTTOM)
    cancelbutton.place(rely=0.93, relx=0.5, anchor='center')


# In[21]:


# Required vars
global seacrh_value
search_value = tkinter.StringVar()

# Passkeep Title
passkeep_title = Label(mainCanvas, text="PassKeep", height=2)
passkeep_title['font'] = title
passkeep_title.place(rely=0.05, relx=0.5, anchor="center")

# Search Title
search_title = Label(mainCanvas, text="Search", height=2)
search_title['font'] = subtitle
search_title.place(rely=0.125, relx=0.5, anchor="center")

# Search bar
url_search_label = tkinter.Label(mainCanvas, text="Website URL:")
url_search_label.place(relx=0.1, rely=0.2, anchor='center')

global search_entry
search_entry = tkinter.Entry(mainCanvas, textvariable=search_value)
search_entry.bind('<Return>', searchPassword)
search_entry.place(relx=0.28, rely=0.2, relwidth=0.25, anchor='center')

# Clear Button
clear_button = tkinter.Button(mainCanvas, text="Clear", command=clearButton)
clear_button.place(relx=0.44, rely=0.2, anchor='center')

# Search Button
search_button = tkinter.Button(mainCanvas, text="Search", command=searchPassword)
search_button.place(relx=0.51, rely=0.2, anchor='center')

# Copy Label
url_search_label = tkinter.Label(mainCanvas, text="Copy Selected:")
url_search_label.place(relx=0.8, rely=0.16, anchor='center')

# Copy url Button
cpurl_button = tkinter.Button(mainCanvas, text="URL", width=6, command=cpURL)
cpurl_button.place(relx=0.7, rely=0.2, anchor='center')

# Copy username Button
cpusername_button = tkinter.Button(mainCanvas, text="Username", width=6, command=cpUsername)
cpusername_button.place(relx=0.8, rely=0.2, anchor='center')

# Copy password Button
cppassword_button = tkinter.Button(mainCanvas, text="Password", width=6, command=cpPassword)
cppassword_button.place(relx=0.9, rely=0.2, anchor='center')

# Results frame
results_frame = Frame(mainCanvas, bg="#ffffff")
results_frame.place(relx=0.5, rely=0.25, relwidth=0.9, relheight=0.65, anchor='n')

# Account credencials output #
##############################

# Style the treeview
style = ttk.Style()

# Pick a treeview theme
style.theme_use("default")

# Configure treeview colours
style.configure("Treeview",
               background='white',
               foreground='black',
               rowheight=35,
               fieldbackground='white'
               )

# Change selected colour
style.map('Treeview',
         background=[('selected', '#9bdee8')],
         foreground=[('selected', 'black')])

# Add Scroll bar
tree_scroll = Scrollbar(mainCanvas)
tree_scroll.place(relx=0.95, rely=0.25, relheight=0.65, anchor='nw')

# Create Tree View
search_tree = ttk.Treeview(results_frame, yscrollcommand=tree_scroll.set, selectmode="browse")

# Configure scroll bar
tree_scroll.config(command=search_tree.yview)

# Define columns
search_tree['columns'] = ("Name", "Website URL", "Username", "Password")

# Format columns
search_tree.column("#0", width=0, stretch=NO, anchor=CENTER)
search_tree.column("Name", width=115, anchor=CENTER)
search_tree.column("Website URL", width=284, anchor=CENTER)
search_tree.column("Username", width=284, anchor=CENTER)
search_tree.column("Password", width=284, anchor=CENTER)

# Create Headings
search_tree.heading("#0", text="Label")
search_tree.heading("Name", text="Name")
search_tree.heading("Website URL", text="Website URL")
search_tree.heading("Username", text="Username")
search_tree.heading("Password", text="Password")
search_tree.bind('<ButtonRelease-2>', showPassword)

# Load Tree
search_tree.place(x=0, y=0, relheight=1, relwidth=1)

# Quit buttom
quit = Button(mainCanvas, text="Quit", width=10, height=1, command=root.destroy)
quit.place(rely=0.95, relx=0.2, anchor='center')

# Logout button
logout = Button(mainCanvas, text="Logout", width=10, height=1, command=logout)
logout.place(rely=0.95, relx=0.4, anchor='center')

# Add password button
addPassword = Button(mainCanvas, text="Add (+)", width=10, height=1, command=addPopup)
addPassword.place(rely=0.95, relx=0.6, anchor='center')

# Remove selected button
remove_selected = Button(mainCanvas, text="Remove (-)", width=10, height=1, command=confirmRemove)
remove_selected.place(rely=0.95, relx=0.8, anchor='center')


# In[22]:


# Login Popup
if s_uname or s_mp or s_salt == "":
    loginPopup()


# In[23]:


root.mainloop()


# ##### 
