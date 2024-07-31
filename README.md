# Livy Dental Analytics
Livy Dental Analytics is a data processing and reporting application designed to manage and analyze financial data for Livy Dental. The application uploads, processes, and stores financial transaction data into a MySQL database, preventing duplicates and ensuring accurate reporting.

# Features
File Upload and Processing: Upload financial transaction files in Excel format. The application processes these files, saves the data into a staging table, and further into a reporting table in MySQL.
Duplicate Prevention: The application uses hash keys to identify and prevent duplicate records from being saved in both staging and reporting tables.
Dynamic Data Handling: Handles multiple types of financial accounts, mapping account names using a predefined configuration.
Dashboard View: Provides a link to a dashboard for visualizing and analyzing the processed data.
User Authentication: Secure login system for users to access the application.

# Installation
1. Clone the Repository:

git clone https://github.com/Abinaya1399/Livy_Dental_Analytics.git

cd Livy_Dental_Analytics

2. Install Dependencies:

pip install -r requirements.txt

3. Configuration:

Update config.py with the necessary configurations including account mappings and file paths.
Ensure MySQL is running and accessible with the credentials provided in app.py.

4. Database Setup:

Ensure the database livy_database is created in MySQL.
The application will automatically create necessary tables (staging_table, reporting_table, file_hashes) if they don't exist.

# Usage
1. Run the Application:

python app.py

This will start the Flask server on http://127.0.0.1:5000.

2. Login:

Navigate to the login page and use the credentials specified in config.py to access the application.

3. Upload Files:

Use the "Process Files" feature to upload and process financial data files. The system will display processed and duplicate files.

4. View Dashboard:

Use the "View Dashboard" button to access the data visualization dashboard (external link to Power BI).
