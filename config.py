# all the imports
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash

# configuration
DATABASE = '/tmp/productivity.db'
DEBUG = True
SECRET_KEY = 'N(._.,OH $L~1scf{/fJ+/EYbko{o4Nqsk}{E7zj:H##2 YK-,Ik`P(@.F*/O<#m'
USERNAME = 'admin'
PASSWORD = 'default'