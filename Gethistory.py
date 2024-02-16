import sqlite3
import os

def get_browser_data(browser="Chrome"):
    if browser.lower() == "chrome":
        # Path to Chrome user data directory
        user_data_path = os.path.expanduser("~") + "/AppData/Local/Google/Chrome/User Data"
        history_db_path = os.path.join(user_data_path, "Default", "History")
        cookies_db_path = os.path.join(user_data_path, "Default", "Cookies")

        # Attempt to connect to the History database, with a retry mechanism
        attempts = 0
        max_attempts = 3
        while attempts < max_attempts:
            try:
                history_conn = sqlite3.connect(history_db_path)
                history_cursor = history_conn.cursor()
                history_cursor.execute("SELECT * FROM urls ORDER BY last_visit_time DESC LIMIT 3000")
                history_results = history_cursor.fetchall()
                break
            except sqlite3.OperationalError as e:
                print(f"Error accessing history database: {e}. Retrying...")
                attempts += 1

        # Print browser history
        print("Browser History:")
        for row in history_results:
            print(row)

        # Close database connections
        history_conn.close()

# Example usage
get_browser_data(browser="Chrome")
