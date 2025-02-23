import requests
from typing import Dict, Optional
from azure.identity import ClientSecretCredential

class AzureAuthenticator:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        # Add Microsoft Graph scope and token URL
        self.scope = "https://management.azure.com/.default"
        self.token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    
    def get_access_token(self) -> Optional[str]:
        try:
            data = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scope': self.scope
            }
            
            response = requests.post(self.token_url, data=data)
            
            if response.status_code == 200:
                return response.json().get('access_token')
            else:
                print(f"Token request failed: {response.text}")
                return None
                
        except Exception as e:
            print(f"Authentication error: {str(e)}")
            return None

    def get_headers(self) -> Dict[str, str]:
        token = self.get_access_token()
        if token:
            return {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
        return {}

    def get_graph_headers(self) -> Dict[str, str]:
        """Get headers for Microsoft Graph API calls"""
        try:
            # Get token for Microsoft Graph
            scope = "https://graph.microsoft.com/.default"
            token = self.credential.get_token(scope)
            
            if not token:
                print("Failed to get Microsoft Graph token")
                return {}
                
            return {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }
        except Exception as e:
            print(f"Error getting Graph headers: {str(e)}")
            return {}
