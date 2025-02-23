# Azure Subscription Security Inspector

A simple tool that analyzes security settings across your Azure subscriptions. It uses REST calls and Azure Resource Graph to gather information about Microsoft Defender status, security recommendations, and RBAC configurations.

![image](https://github.com/user-attachments/assets/fe34340f-b71f-4191-a0dd-3a2519d1b60f)

## Features

- Fetch a list of available Azure subscriptions  
- Analyze Microsoft Defender configurations  
- Gather security recommendations from Defender for Cloud  
- Review RBAC assignments to highlight privileged roles  

## Requirements

- Python 3.7+  
- Dependencies listed in [requirements.txt](./requirements.txt):  
  - requests  
  - python-dotenv  
  - azure-identity  
  - azure-mgmt-resourcegraph  

## Required Permissions

Before running the script, ensure your service principal has the following permissions:

1. **Directory.Read.All**  
   - Needed to enumerate and read properties of Azure AD resources (e.g., applications, roles, etc.).

2. **User.ReadWrite**  
   - Required if you plan on making updates to certain user or directory objects.  
   - If you only need read access, consider using a more restrictive permission like `User.Read`.

3. **Security Reader** (assigned at the Management Group level)  
   - Allows the script to read security-related data across all subscriptions in the tenant, ensuring you have visibility into Defender statuses and security recommendations in each subscription.

Make sure you grant these permissions securely and only to the principal (service principal or user) that needs them.  

## Installation and Usage

1. **Clone or download the repository:**
   ```bash
   git clone https://github.com/<your_repo>/azure-subscription-security-inspector.git
   ```
   or simply download the ZIP file and extract it.

2. **Install the required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Create a `.env` file and set the following environment variables:**
   ```bash
   AZURE_TENANT_ID=<your tenant>
   AZURE_CLIENT_ID=<your client id>
   AZURE_CLIENT_SECRET=<your client secret>
   ```
   Make sure the `.env` file is in the same directory as `main.py`.

4. **Run the application:**
   ```bash
   python main.py
   ```

5. **Use the GUI to select a subscription** you want to analyze for security settings.  
