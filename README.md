# KidsTube Project

This project is named as KidsTube.

## Configuration

Please make sure that you have Python installed on your machine, including packages like pip and some virtual environment managers like virtualenv, venv, pyenv, etc.

Please make sure to create a new virtual environment on your machine and then make sure to activate it before starting with the installation.

## Installation

You can install/run the app directly on your OS using the instructions below (**This instructions are for Windows 10+, so if you use another OS you need to figure out the instructions for your specific case**).

Setup a virtualenv and install requirements. This example uses venv, so you need to run the following commands in order to create the virtual environment, activate it and then install the dependencies:

Creating the virtual environment:
```bash
python -m venv env
```
Activating the virtual environment:
```bash
.\env\Scripts\activate
```
The above command activates the virtual environment, so now you should be able to see the env name in parenthesis on the left side of the terminal.

Installing the requirements:
```bash
pip install -r requirements.txt
```

## Set Up the Database

For this project we´re using PostgreSQL 17.

Please make sure that your DB was created according to the data connection strings that are defined under DATABASES in settings.py file.

In order to be able to generate the right migration files that will be sent to the DB, you need to run this command:

```bash
python manage.py makemigrations
```

In order to be able to create/update the tables into the DB, you need to run the following command:

```bash
python manage.py migrate
```

Please go to PgAdmin and enter to your local server connection and then, validate that all tables are inside the DB you created before.

## Collecting Static Files

If we have the `Debug = False` value in the `settings.py` file (recommended), we need to serve the static files in the application to make them available and therefore, we can see static files like images, css files, etc. In order to do this, we need to run the following command on our terminal:
```bash
python manage.py collectstatic
```
After that, validate that there's a new folder created named as `static_root`.

## Creating a superuser to use the Django Admin Page (optional)

If we want to use the Django Admin Page, we need to create a superuser that has the necessary rights to log in to this page. This page is important if we as developers want to check data related stuff
without having to check the DB directly every time.

In order to create a superuser, we have created a custom script that does it automatically, so we have to run this command:
```bash
python manage.py add_default_superuser
```
Now, if you see on the console an INFO log message indicating that a default usperuser with username admin was created, we can run the server again (see the section below) and then, we can go to `localhost:8000/admin/` and there, in the login page we log in with username = `admin` and password = `12345` and now, if everything was successful, you should be able to see some data stuff there.

**Note: After you have run the above command, you can continue running it more times, but it won't create more superusers, since it will only create it if it doesn't exist, otherwise, the script skips that user creation automatically.**

## Running Server

```bash
python manage.py runserver
```
As of now, you can go to `localhost:8000` on your desired browser and start using the application.

## Leaving the virtual environment

```bash
deactivate
```

Validate that there's no env name in parenthesis on the left side of the terminal.