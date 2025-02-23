from auth import AzureAuthenticator
from gui import SecurityAnalyzerGUI
import os
from dotenv import load_dotenv
import tkinter as tk

def main():
    # Load environment variables
    load_dotenv()
    
    # Initialize authentication
    authenticator = AzureAuthenticator(
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET")
    )
    
    # Test authentication
    headers = authenticator.get_headers()
    if not headers:
        print("Failed to get authentication headers")
        return
        
    print("Authentication headers obtained successfully")
    
    # Initialize GUI with authenticator
    root = tk.Tk()
    app = SecurityAnalyzerGUI(root, authenticator)
    root.mainloop()

if __name__ == "__main__":
    main()
