import requests
from typing import List, Dict, Optional

# Import required classes for Resource Graph queries
from azure.identity import ClientSecretCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest

class AzureOperations:
    def __init__(self, authenticator):
        self.authenticator = authenticator
        self.base_url = "https://management.azure.com"
        
    def get_subscriptions(self) -> List[Dict[str, str]]:
        """Fetch all available subscriptions"""
        try:
            headers = self.authenticator.get_headers()
            if not headers:
                print("Failed to get authentication headers")
                return []
                
            url = f"{self.base_url}/subscriptions?api-version=2020-01-01"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            subscriptions = response.json().get('value', [])
            return [{
                'id': sub['subscriptionId'], 
                'name': sub['displayName'],
                'tags': sub.get('tags', {})  # Dodajemy tagi
            } for sub in subscriptions]
            
        except Exception as e:
            print(f"Error fetching subscriptions: {str(e)}")
            return []

    def analyze_subscription_security(self, subscription_id: str) -> Dict[str, any]:
        """Analyze security settings for a given subscription"""
        try:
            headers = self.authenticator.get_headers()
            if not headers:
                return {"error": "Failed to get authentication headers"}

            results = {}
            
            # Check Microsoft Defender for Cloud using the REST API
            defender_status = self._check_defender_status(subscription_id, headers)
            results["Microsoft Defender"] = defender_status

            # Check Security Center recommendations using Resource Graph
            security_center = self._check_security_center(subscription_id)
            results["Security Center"] = security_center

            # Check RBAC assignments using the REST API
            rbac = self._check_rbac(subscription_id, headers)
            results["RBAC Settings"] = rbac

            return results

        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}

    def _check_defender_status(self, subscription_id: str, headers: Dict) -> Dict[str, any]:
        """Check Microsoft Defender for Cloud settings"""
        try:
            url = f"{self.base_url}/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings?api-version=2023-01-01"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            services = response.json().get('value', [])
            return {
                "status": "Completed",
                "details": [
                    {
                        "name": service['name'],
                        "tier": service['properties']['pricingTier']
                    } for service in services
                ]
            }
        except Exception as e:
            return {"status": "Failed", "error": str(e)}

    def _check_security_center(self, subscription_id: str) -> Dict[str, any]:
        """Fetch security recommendations via Azure Resource Graph"""
        try:
            # Build a ClientSecretCredential using SPN details from the authenticator
            credential = ClientSecretCredential(
                tenant_id=self.authenticator.tenant_id,
                client_id=self.authenticator.client_id,
                client_secret=self.authenticator.client_secret
            )
            # Create the ResourceGraphClient
            resource_client = ResourceGraphClient(credential)
            
            # Define a KQL query to fetch assessments for unhealthy resources
            query = """
            securityresources
            | where type =~ "microsoft.security/assessments" and properties.status.code =~ "Unhealthy"
            | extend severity = tostring(properties.metadata.severity)
            | extend resourceId = tostring(properties.resourceDetails.Id)
            | project displayName = properties.displayName, severity, resourceId
            """
            request = QueryRequest(
                subscriptions=[subscription_id],
                query=query
            )
            response = resource_client.resources(request)
            
            # Initialize counters and recommendation groups
            severity_counts = {"high": 0, "medium": 0, "low": 0}
            recommendations = {
                "high": {},    # Dictionary to store high recommendations and their counts
                "medium": {},  # Dictionary to store medium recommendations and their counts
                "low": {}     # Dictionary to store low recommendations and their counts
            }
            
            if response and response.data:
                for row in response.data:
                    severity = row.get("severity", "").lower()
                    name = row.get("displayName", "Unnamed Recommendation")
                    
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                        if name in recommendations[severity]:
                            recommendations[severity][name] += 1
                        else:
                            recommendations[severity][name] = 1
            
            # Format recommendations with resource counts
            formatted_recommendations = {
                "high": [f"{name} ({count} resources)" for name, count in recommendations["high"].items()],
                "medium": [f"{name} ({count} resources)" for name, count in recommendations["medium"].items()],
                "low": [f"{name} ({count} resources)" for name, count in recommendations["low"].items()]
            }
            
            return {
                "status": "Completed",
                "recommendations": {
                    "high_priority": formatted_recommendations["high"],
                    "medium_priority": formatted_recommendations["medium"],
                    "low_priority": formatted_recommendations["low"],
                    "total_high": severity_counts["high"],
                    "total_medium": severity_counts["medium"],
                    "total_low": severity_counts["low"]
                }
            }
        except Exception as e:
            return {"status": "Failed", "error": str(e)}

    def _check_rbac(self, subscription_id: str, headers: Dict) -> Dict[str, any]:
        """Check RBAC configuration"""
        try:
            # Update privileged roles list
            privileged_roles = {
                "Owner",
                "Contributor",
                "Access Review Operator Service Role",
                "Role Based Access Control Administrator",
                "User Access Administrator"
            }

            # Get role assignments
            assignments_url = f"{self.base_url}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
            assignments_response = requests.get(assignments_url, headers=headers)
            assignments_response.raise_for_status()
            assignments = assignments_response.json().get('value', [])

            # Get role definitions
            roles_url = f"{self.base_url}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
            roles_response = requests.get(roles_url, headers=headers)
            roles_response.raise_for_status()
            roles = {role['name']: role['properties']['roleName'] 
                    for role in roles_response.json().get('value', [])}

            # Get principal names (users/groups/service principals)
            graph_url = "https://graph.microsoft.com/v1.0"
            graph_headers = self.authenticator.get_graph_headers()
            
            privileged_assignments = []
            normal_assignments = []

            for assignment in assignments:
                role_id = assignment['properties']['roleDefinitionId'].split('/')[-1]
                principal_id = assignment['properties']['principalId']
                role_name = roles.get(role_id, role_id)
                
                # Try to get principal details from Microsoft Graph
                principal_url = f"{graph_url}/directoryObjects/{principal_id}"
                principal_response = requests.get(principal_url, headers=graph_headers)
                
                if principal_response.status_code == 200:
                    principal_data = principal_response.json()
                    principal_name = principal_data.get('displayName', principal_id)
                    principal_type = principal_data.get('@odata.type', '').split('.')[-1]
                else:
                    principal_name = principal_id
                    principal_type = "Unknown"

                assignment_info = {
                    'role': role_name,
                    'principalName': principal_name,
                    'principalType': principal_type
                }

                if role_name in privileged_roles:
                    privileged_assignments.append(assignment_info)
                else:
                    normal_assignments.append(assignment_info)

            return {
                "status": "Completed",
                "total_assignments": len(assignments),
                "details": {
                    "privileged": privileged_assignments,
                    "normal": normal_assignments
                }
            }
        except Exception as e:
            return {"status": "Failed", "error": str(e)}
