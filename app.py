from flask import Flask, request, render_template, session, redirect, url_for, flash
import pandas as pd
import mysql.connector
import os
import logging
import secrets
from flask_session import Session
from datetime import datetime
from config import ACCOUNT_TYPE_MAP, LOGIN_CREDENTIALS, PROCESS_FOLDER, ARCHIVE_FOLDER, DASHBOARD_URL
import hashlib
import pandas as pd
import mysql.connector

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session'
Session(app)

db_config = {
    'user': 'root',
    'password': 'root',
    'host': 'localhost',
    'database': 'livy_database',
    'port': 8889
}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_file_hash_key(file_path):
    """Generates a SHA256 hash key for the contents of a file."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def generate_row_hash_key(row):
    """Generates a SHA256 hash key for a given row."""
    hasher = hashlib.sha256()

    row_content = ''.join(str(value) for value in row)
    hasher.update(row_content.encode('utf-8'))
    return hasher.hexdigest()

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username == LOGIN_CREDENTIALS['username'] and password == LOGIN_CREDENTIALS['password']:
        session['logged_in'] = True
        return redirect(url_for('process_files'))
    else:
        return render_template('login.html', error="Invalid username or password")

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/process_files')
def process_files():
    if not session.get('logged_in'):
        return redirect(url_for('index'))

    files_exist = any(
        filename.endswith('.xlsx') or filename.endswith('.csv')
        for filename in os.listdir(PROCESS_FOLDER)
    )

    if not files_exist:
        flash("No files exist for processing!", 'info')

    return render_template('process_files.html', files_exist=files_exist)

@app.route('/confirm_process', methods=['POST'])
def confirm_process():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    try:
        files_processed = []
        duplicate_files = []
        duplicate_summary = {}
        for filename in os.listdir(PROCESS_FOLDER):
            if filename.endswith('.xlsx') or filename.endswith('.csv'):
                file_path = os.path.join(PROCESS_FOLDER, filename)
                for key in ACCOUNT_TYPE_MAP.keys():
                    if key in filename:
                        mapped_account_type = ACCOUNT_TYPE_MAP[key]
                        break
                else:
                    mapped_account_type = "Unknown"

                status, duplicates = process_file(file_path, mapped_account_type)
                if status == "success":
                    files_processed.append(filename)
                elif status == "duplicate":
                    duplicate_files.append(filename)
                if duplicates:
                    for account, date_range in duplicates.items():
                        if account in duplicate_summary:
                            existing_min_date, existing_max_date = duplicate_summary[account]
                            new_min_date = min(existing_min_date, date_range[0])
                            new_max_date = max(existing_max_date, date_range[1])
                            duplicate_summary[account] = (new_min_date, new_max_date)
                        else:
                            duplicate_summary[account] = date_range

        if files_processed:
            flash_message = "<table class='table table-striped'><thead><tr><th>Processed Files</th></tr></thead><tbody>"
            for file in files_processed:
                flash_message += f"<tr><td>{file}</td></tr>"
            flash_message += "</tbody></table>"
            flash(flash_message, 'info')

        if duplicate_files:
            duplicate_message = "<table class='table table-warning'><thead><tr><th>Duplicate Files</th></tr></thead><tbody>"
            for file in duplicate_files:
                duplicate_message += f"<tr><td>{file}</td></tr>"
            duplicate_message += "</tbody></table>"
            flash(duplicate_message, 'warning')

        if duplicate_summary:
            duplicate_summary_message = "<div class='alert alert-warning' role='alert'><strong>Duplicate Records Found:</strong><ul>"
            for account, (min_date, max_date) in duplicate_summary.items():
                duplicate_summary_message += f"<li>Account {account}: From {min_date} to {max_date}</li>"
            duplicate_summary_message += "</ul></div>"
            flash(duplicate_summary_message, 'warning')

        if not files_processed and not duplicate_files:
            flash("No files to process!", 'info')

        return redirect(url_for('process_files'))
    except Exception as e:
        logger.error(f"Error processing files: {e}")
        flash(f"Error processing files: {e}", 'danger')
        return redirect(url_for('process_files'))


def process_file(file_path, account_type):
    try:
        file_hash_key = generate_file_hash_key(file_path)
        file_name = os.path.basename(file_path)

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM file_hashes WHERE hash_key = %s", (file_hash_key,))
        if cursor.fetchone()[0] > 0:
            logger.info(f"File {file_path} has already been processed. Skipping.")
            return "duplicate", None

        cursor.execute(
            "INSERT INTO file_hashes (file_path, file_name, hash_key, account_type, processed_date) VALUES (%s, %s, %s, %s, NOW())",
            (file_path, file_name, file_hash_key, account_type)
        )
        conn.commit()

        original_df = pd.read_excel(file_path)

        # Convert 'Posting Date' to datetime format
        original_df['Posting Date'] = pd.to_datetime(original_df['Posting Date'], errors='coerce')

        # Drop rows with invalid dates if necessary
        original_df.dropna(subset=['Posting Date'], inplace=True)

        # Extract the year from the 'Posting Date' column
        year = original_df['Posting Date'].dt.year.mode()[0]
        year = int(year)

        duplicates_summary = save_to_staging_table(original_df, account_type, year)
        create_reporting_table(account_type, year)

        cursor.close()
        conn.close()
        return "success", duplicates_summary
    except Exception as e:
        logger.error(f"Error processing file: {e}")
        raise


def save_to_staging_table(df, account_type, year):
    try:
        df['account_type'] = account_type
        df['year'] = year

        required_columns = ['Details', 'Posting Date', 'Description', 'Amount', 'Type', 'Balance', 'Check or Slip #']
        for col in required_columns:
            if col not in df.columns:
                df[col] = None

        df.fillna({
            'Details': '',
            'Posting Date': pd.to_datetime('1970-01-01'),
            'Description': '',
            'Amount': 0.0,
            'Type': '',
            'Balance': 0.0,
            'Check or Slip #': ''
        }, inplace=True)

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS staging_table (
                id INT AUTO_INCREMENT PRIMARY KEY,
                details VARCHAR(255),
                posting_date DATETIME,
                description TEXT,
                amount DECIMAL(10, 2),
                type VARCHAR(255),
                balance DECIMAL(10, 2),
                check_or_slip VARCHAR(255),
                account_type VARCHAR(255),
                year INT,
                row_hash VARCHAR(64) UNIQUE
            )
        """)

        duplicate_ids = []
        duplicate_dates = []
        for index, row in df.iterrows():
            row_hash_key = generate_row_hash_key(row)
            cursor.execute("SELECT id, posting_date FROM staging_table WHERE row_hash = %s", (row_hash_key,))
            existing_row = cursor.fetchone()
            if existing_row is None:
                cursor.execute(
                    """
                    INSERT INTO staging_table (details, posting_date, description, amount, type, balance, check_or_slip, account_type, year, row_hash)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (row['Details'], row['Posting Date'], row['Description'], row['Amount'], row['Type'], row['Balance'], row['Check or Slip #'], account_type, year, row_hash_key)
                )
            else:
                duplicate_ids.append(existing_row[0])
                duplicate_dates.append(existing_row[1])

        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Data successfully saved to staging table.")

        if duplicate_ids:
            min_date = min(duplicate_dates).strftime('%B %Y')
            max_date = max(duplicate_dates).strftime('%B %Y')
            return {account_type: (min_date, max_date)}
        return {}
    except Exception as e:
        logger.error(f"Error saving to staging table: {e}")
        raise



def create_reporting_table(account_type, year):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reporting_table (
                id INT AUTO_INCREMENT PRIMARY KEY,
                year INT,
                quarter VARCHAR(2),
                month INT,
                actual_date DATE,
                account_type VARCHAR(255),
                category VARCHAR(255),
                sub_category VARCHAR(255),
                amount DECIMAL(10, 2)
            )
        """)

        cursor.execute("SELECT * FROM staging_table WHERE account_type = %s AND year = %s", (account_type, year))
        staging_data = cursor.fetchall()

        if not staging_data:
            logger.info(f"No data found in staging table for {account_type} {year}.")
            return

        staging_df = pd.DataFrame(staging_data, columns=cursor.column_names)

        if staging_df.empty:
            logger.info(f"No data to process for {account_type} {year}.")
            return

        staging_df['Category'], staging_df['Sub-Category'] = zip(*staging_df['description'].map(lambda desc: assign_category_subcategory_keyword(desc, conn)))

        staging_df['quarter'] = staging_df['posting_date'].dt.quarter.apply(lambda x: f"Q{x}")
        staging_df['month'] = staging_df['posting_date'].dt.month
        staging_df['actual_date'] = staging_df['posting_date']

        for index, row in staging_df.iterrows():
            try:
                cursor.execute(
                    """
                    INSERT INTO reporting_table (id, year, quarter, month, actual_date, account_type, category, sub_category, amount)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (row['id'], row['year'], row['quarter'], row['month'], row['actual_date'], row['account_type'], row['Category'], row['Sub-Category'], row['amount'])
                )
            except mysql.connector.IntegrityError as e:
                if e.errno == 1062:  # Duplicate entry error code for MySQL
                    logger.info(f"Duplicate record found for id {row['id']} in account {account_type}")
                    continue  # Skip duplicate entry and continue with the next record

        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Data successfully saved to reporting table.")
    except Exception as e:
        logger.error(f"Error creating reporting table: {e}")
        raise

def assign_category_subcategory_keyword(description, conn):
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT keyword, category, sub_category FROM lookup_table")
    keywords_df = pd.DataFrame(cursor.fetchall())

    description_normalized = description.replace(" ", "").lower()

    for index, row in keywords_df.iterrows():
        keyword_normalized = row['keyword'].replace(" ", "").lower()
        if keyword_normalized in description_normalized:
            return row['category'], row['sub_category']
    return None, None

@app.route('/view_dashboard')
def view_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return redirect(DASHBOARD_URL)

if __name__ == '__main__':
    app.run(debug=True)
