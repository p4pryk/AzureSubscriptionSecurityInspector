import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
import tkinter.font as tkfont
from subscription_analyzer import AzureOperations
import re

class SecurityAnalyzerGUI:
    def __init__(self, root, authenticator):
        self.root = root
        self.root.title("Azure Subscription Security Inspector")
        self.root.geometry("1200x800") 
        self.authenticator = authenticator
        self.azure_ops = AzureOperations(authenticator)
        self.subscriptions = []
        
        # Define icons for different sections
        self.icons = {
            "Microsoft Defender Status": "🛡️",
            "Security Recommendations": "🔒",
            "RBAC Settings": "👥"
        }
        
        self.setup_gui()
        self.load_subscriptions()

    def setup_gui(self):
        # Modern color scheme
        self.colors = {
            'background': '#ffffff',      # Pure white
            'surface': '#f8f9fa',        # Light gray for cards
            'primary': '#0078d4',        # Azure blue
            'secondary': '#50e6ff',      # Light blue
            'text': '#323130',          # Dark gray
            'text_dim': '#605e5c',      # Medium gray
            'success': '#107c10',       # Green
            'error': '#d13438',         # Red
            'border': '#e1e1e1'         # Light border
        }

        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure modern styles
        style.configure('Modern.TFrame',
                       background=self.colors['background'],
                       relief='flat')
        
        style.configure('Card.TFrame',
                       background=self.colors['surface'],
                       relief='solid',
                       borderwidth=1,
                       borderradius=8)  # Zaokrąglone rogi
        
        style.configure('Header.TLabel',
                       background=self.colors['background'],
                       foreground=self.colors['primary'],
                       font=('Segoe UI', 32, 'bold'))
        
        style.configure('Modern.TButton',
                       background=self.colors['primary'],
                       foreground='white',
                       padding=(20, 10),
                       font=('Segoe UI', 10),
                       borderradius=6)  # Zaokrąglony przycisk
        
        # Dodaj hover effect dla przycisku
        style.map('Modern.TButton',
            background=[('active', self.colors['secondary'])],
            foreground=[('active', 'white')])

        # Main window configuration
        self.root.configure(bg=self.colors['background'])
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(2, weight=1)

        # Modern header with icon
        header_frame = ttk.Frame(self.root, style='Modern.TFrame', padding="30 20")
        header_frame.grid(row=0, column=0, sticky="ew")
        
        # Logo and title in one line
        logo_label = ttk.Label(
            header_frame,
            text="🛡️",  # Shield emoji as logo
            font=('Segoe UI', 40),
            background=self.colors['background']
        )
        logo_label.pack(side="left", padx=(0, 15))

        title_frame = ttk.Frame(header_frame, style='Modern.TFrame')
        title_frame.pack(side="left")

        header_label = ttk.Label(
            title_frame,
            text="Azure Subscription Security Inspector",
            style='Header.TLabel'
        )
        header_label.pack(anchor="w")

        subtitle_label = ttk.Label(
            title_frame,
            text="Azure Subscription Security Inspector\n" +
             "Monitor and assess your Azure resources’ security posture, including in-depth evaluations of Microsoft Defender and RBAC configurations.\n" +
             "This tool provides comprehensive insights into your cloud security, enabling you to identify potential threats, optimize security policies, and ensure compliance with industry standards.\n" +
             "Experience enhanced monitoring and advanced analytics that empower you to take proactive steps toward safeguarding your critical assets in the Azure ecosystem.",
            font=('Segoe UI', 14),
            foreground=self.colors['text_dim'],
            background=self.colors['background']
        )
        subtitle_label.pack(anchor="w")

        # Main content container with card-like appearance
        main_container = ttk.Frame(self.root, style='Modern.TFrame', padding="30")
        main_container.grid(row=2, column=0, sticky="nsew")
        main_container.grid_columnconfigure(1, weight=3)
        main_container.grid_rowconfigure(0, weight=1)

        # Left panel: Controls card with fixed width - zwiększamy szerokość
        controls_card = ttk.Frame(main_container, style='Card.TFrame', padding="20")
        controls_card.grid(row=0, column=0, sticky="ns", padx=(0, 20))  # Zwiększamy padding między panelami
        controls_card.grid_propagate(False)  # Prevent the frame from expanding
        controls_card.configure(width=390)   # Zwiększamy z 300 na 350
        
        # Heading for controls section
        controls_header = ttk.Label(
            controls_card,
            text="Control Panel",
            font=('Segoe UI', 14, 'bold'),
            foreground=self.colors['primary'],  # Change from 'text' to 'primary'
            background=self.colors['surface']
        )
        controls_header.pack(anchor="w", pady=(0, 10))

        # Status indicator with icon - przenosimy tutaj
        self.status_label = ttk.Label(
            controls_card,
            text="Status: Ready",  # Zmieniamy tekst
            font=('Segoe UI', 11),
            foreground=self.colors['success'],
            background=self.colors['surface']
        )
        self.status_label.pack(anchor="w", pady=(0, 20))

        # Subscription selector with modern styling
        sub_label = ttk.Label(
            controls_card,
            text="SELECT SUBSCRIPTION",
            font=('Segoe UI', 9, 'bold'),
            foreground=self.colors['text_dim'],
            background=self.colors['surface']
        )
        sub_label.pack(anchor="w", pady=(0, 5))

        self.sub_dropdown = ttk.Combobox(
            controls_card,
            state="readonly",
            font=('Segoe UI', 10),
            width=34
        )
        self.sub_dropdown.pack(fill="x", pady=(0, 15))

        # Modern analyze button
        load_button = ttk.Button(
            controls_card,
            text="Analyze Subscription",
            command=self.load_subscription,
            style='Modern.TButton'
        )
        load_button.pack(fill="x", pady=(0, 15))

        # Sekcja informacji o subskrypcji z ustaloną szerokością
        self.sub_info_frame = ttk.Frame(controls_card, style='Card.TFrame', padding="15", width=370)
        self.sub_info_frame.pack(fill="x", pady=(0, 15))
        # Nie wyłączamy propagacji rozmiaru – wtedy wysokość dostosuje się do zawartości

        # Nagłówek dla sekcji informacji o subskrypcji
        self.sub_info_label = ttk.Label(
            self.sub_info_frame,
            text="Subscription Information",
            font=('Segoe UI', 12, 'bold'),
            foreground=self.colors['primary'],
            background=self.colors['surface'],
            wraplength=350,
            anchor="w",
            justify="left"
        )
        self.sub_info_label.pack(anchor="w", pady=(0, 10))

        # Etykiety danych subskrypcji – ustawienie wyrównania i zawijanie tekstu
        self.sub_name_label = ttk.Label(
            self.sub_info_frame,
            text="Name: Not selected",
            font=('Segoe UI', 10),
            foreground=self.colors['text'],
            background=self.colors['surface'],
            wraplength=350,
            anchor="w",
            justify="left"
        )
        self.sub_name_label.pack(fill="x", pady=(0, 5))

        self.sub_id_label = ttk.Label(
            self.sub_info_frame,
            text="ID: Not selected",
            font=('Segoe UI', 10),
            foreground=self.colors['text'],
            background=self.colors['surface'],
            wraplength=350,
            anchor="w",
            justify="left"
        )
        self.sub_id_label.pack(fill="x")

        # Etykieta dla tagów
        self.sub_tags_label = ttk.Label(
            self.sub_info_frame,
            text="Tags: No tags",
            font=('Segoe UI', 10),
            foreground=self.colors['text'],
            background=self.colors['surface'],
            wraplength=350,
            anchor="w",
            justify="left"
        )
        self.sub_tags_label.pack(fill="x", pady=(5, 0))

        # Right panel: Results card - zwiększamy padding
        results_card = ttk.Frame(main_container, style='Card.TFrame', padding="25")  # Zwiększamy padding
        results_card.grid(row=0, column=1, sticky="nsew", padx=(0, 20))  # Dodajemy padding z prawej
        results_card.grid_columnconfigure(0, weight=1)
        results_card.grid_rowconfigure(1, weight=1)

        # Results header
        results_header = ttk.Label(
            results_card,
            text="Security Analysis Results",
            font=('Segoe UI', 14, 'bold'),
            foreground=self.colors['primary'],  # Change from 'text' to 'primary'
            background=self.colors['surface']
        )
        results_header.grid(row=0, column=0, sticky="w", pady=(0, 15))

        # Results text area with modern styling
        self.recommendations_text = scrolledtext.ScrolledText(
            results_card,
            wrap=tk.WORD,
            font=('Segoe UI', 10),
            background=self.colors['background'],
            foreground=self.colors['text'],
            insertbackground=self.colors['text'],
            selectbackground=self.colors['primary'],
            selectforeground='white',
            relief='flat',
            padx=15,
            pady=10,
            state='disabled'  # Make the widget read-only
        )
        self.recommendations_text.grid(row=1, column=0, sticky="nsew")

        self.setup_text_styles()

    def setup_text_styles(self):
        base_font = 'Segoe UI'
        base_size = 10
        
        self.text_styles = {
            "section": {
                "font": (base_font, base_size + 6, "bold"),
                "spacing": 1,  # Reduced from 2 to 1
                "foreground": self.colors['primary']
            },
            "info": {
                "font": (base_font, base_size, "italic"),
                "spacing": 1,
                "foreground": self.colors['text_dim']
            },
            "subsection": {
                "font": (base_font, base_size + 1, "bold"),
                "spacing": 1,
                "foreground": self.colors['text']
            },
            "normal": {
                "font": (base_font, base_size),
                "spacing": 0.8,
                "foreground": self.colors['text']
            }
        }

    def load_subscriptions(self):
        self.subscriptions = self.azure_ops.get_subscriptions()
        self.sub_dropdown['values'] = []
        if self.subscriptions:
            self.sub_dropdown['values'] = [sub['name'] for sub in self.subscriptions]
            self.sub_dropdown.set(self.sub_dropdown['values'][0])
        else:
            self.recommendations_text.config(state='normal')
            self.recommendations_text.delete(1.0, tk.END)
            self.recommendations_text.insert(tk.END,
                "No subscriptions found or error occurred while fetching subscriptions.")
            self.recommendations_text.config(state='disabled')

    def load_subscription(self):
        selected_name = self.sub_dropdown.get()
        selected_sub = next((sub for sub in self.subscriptions if sub['name'] == selected_name), None)
        
        if not selected_sub:
            return
            
        # Configure text tags with colors
        for style_name, style_props in self.text_styles.items():
            self.recommendations_text.tag_configure(
                style_name,
                font=style_props["font"],
                spacing1=style_props["spacing"] * 10,
                foreground=style_props["foreground"]
            )

        self.status_label.config(text="Status: Analyzing...")
        
        results = self.azure_ops.analyze_subscription_security(selected_sub['id'])
        if "error" in results:
            self.recommendations_text.insert(tk.END, "❌ Error: ", "section")
            self.recommendations_text.insert(tk.END, f"{results['error']}\n", "normal")

        self.format_results_text(selected_name, selected_sub, results)
        self.status_label.config(text="Status: Analysis complete")

    def format_results_text(self, selected_name, selected_sub, results):
        # Enable widget for text insertion
        self.recommendations_text.config(state='normal')
    
        # Update subscription info in left panel
        self.sub_name_label.config(text=f"Name: {selected_name}")
        self.sub_id_label.config(text=f"ID: {selected_sub['id']}")
        
        # Update tags
        tags = selected_sub.get('tags', {})
        if tags:
            tags_text = "\n".join([f"{k}: {v}" for k, v in tags.items()])
            self.sub_tags_label.config(text=f"Tags:\n{tags_text}")
        else:
            self.sub_tags_label.config(text="Tags: No tags")
        
        # Section descriptions
        section_descriptions = {
            "Microsoft Defender": "Microsoft Defender for Cloud provides unified security management and threat protection across your Azure workloads.",
            "Security Center": "Security recommendations based on Defender for Cloud assessment of your resources and security controls.",
            "RBAC Settings": "Review of Role-Based Access Control (RBAC) assignments that determine who has access to your Azure resources."
        }

        # Clear results text
        self.recommendations_text.delete(1.0, tk.END)

        first_section = True
        for check_name, check_results in results.items():
            display_name = "Microsoft Defender Status" if check_name == "Microsoft Defender" else \
                          "Security Recommendations" if check_name == "Security Center" else \
                          check_name

            # Section title with icon
            if first_section:
                self.recommendations_text.insert(tk.END, f"{self.icons.get(display_name, '▶')} {display_name}\n", "section")
                first_section = False
            else:
                self.recommendations_text.insert(tk.END, f"\n{self.icons.get(display_name, '▶')} {display_name}\n", "section")
            
            # Section description without extra newline
            self.recommendations_text.insert(tk.END, f"{section_descriptions[check_name]}\n", "info")

            if check_results["status"] == "Failed":
                self.recommendations_text.insert(tk.END, "  ❌ Error: ", "section")
                self.recommendations_text.insert(tk.END, f"{check_results['error']}\n", "normal")
                continue

            if (check_name == "Microsoft Defender"):
                # Group services by status
                standard_services = []
                non_standard_services = []
                for service in check_results["details"]:
                    if (service['tier'] == "Standard"):
                        standard_services.append(service['name'])
                    else:
                        non_standard_services.append(service['name'])
                
                if (standard_services):
                    self.recommendations_text.insert(tk.END, "  ✅ Protected Services\n", "subsection")
                    for service in sorted(standard_services):
                        self.recommendations_text.insert(tk.END, f"    • {service}\n", "normal")
                
                if (non_standard_services):
                    self.recommendations_text.insert(tk.END, "  ❌ Unprotected Services\n", "subsection")
                    for service in sorted(non_standard_services):
                        self.recommendations_text.insert(tk.END, f"    • {service}\n", "normal")
                
                # Add newline at the end of section
                self.recommendations_text.insert(tk.END, "\n", "normal")
                
            elif (check_name == "Security Center"):
                recommendations = check_results.get("recommendations", {})
                
                # Insert severity counts right after description
                self.recommendations_text.insert(tk.END, 
                    f"    🔴 High Severity Issues:   {recommendations.get('total_high', 0)}\n"
                    f"    🟡 Medium Severity Issues: {recommendations.get('total_medium', 0)}\n"
                    f"    🔵 Low Severity Issues:    {recommendations.get('total_low', 0)}\n", "normal")
                
                # Detailed recommendations
                for severity, icon in [("high", "❗"), ("medium", "⚠️"), ("low", "ℹ️")]:
                    total = recommendations.get(f"total_{severity}", 0)
                    if (total > 0):
                        self.recommendations_text.insert(tk.END, 
                            f"  {severity.upper()} PRIORITY FINDINGS\n", "subsection")
                        recs = self.group_recommendations(recommendations.get(f"{severity}_priority", []))
                        for rec in recs:
                            self.recommendations_text.insert(tk.END, f"    {icon} {rec}\n", "normal")
                
                # Add newline at the end of section
                self.recommendations_text.insert(tk.END, "\n", "normal")
                
            elif (check_name == "RBAC Settings"):
                self.recommendations_text.insert(tk.END,
                    f"    Total Assignments: {check_results['total_assignments']}\n", "normal")
                
                if (check_results["details"]):
                    # Group users by role for privileged roles
                    privileged_by_role = {}
                    for assignment in check_results["details"]["privileged"]:
                        role = assignment['role']
                        principal = f"{assignment['principalName']} ({assignment['principalType']})"
                        if role not in privileged_by_role:
                            privileged_by_role[role] = []
                        privileged_by_role[role].append(principal)

                    # Display privileged roles
                    if privileged_by_role:
                        self.recommendations_text.insert(tk.END, "  ⚠️ Privileged Role Assignments:\n", "subsection")
                        for role, principals in sorted(privileged_by_role.items()):
                            self.recommendations_text.insert(tk.END, 
                                f"    Role: {role} ({len(principals)} assignments):\n", "normal")
                            for principal in sorted(principals):
                                self.recommendations_text.insert(tk.END, f"      • {principal}\n", "normal")
                        self.recommendations_text.insert(tk.END, "\n", "normal")

                    # Group users by role for standard roles
                    normal_by_role = {}
                    for assignment in check_results["details"]["normal"]:
                        role = assignment['role']
                        principal = f"{assignment['principalName']} ({assignment['principalType']})"
                        if role not in normal_by_role:
                            normal_by_role[role] = []
                        normal_by_role[role].append(principal)

                    # Display normal roles
                    if normal_by_role:
                        self.recommendations_text.insert(tk.END, "  ✅ Standard Role Assignments:\n", "subsection")
                        for role, principals in sorted(normal_by_role.items()):
                            self.recommendations_text.insert(tk.END, 
                                f"    Role: {role} ({len(principals)} assignments):\n", "normal")
                            for principal in sorted(principals):
                                self.recommendations_text.insert(tk.END, f"      • {principal}\n", "normal")

                # Add newline at the end of section
                self.recommendations_text.insert(tk.END, "\n", "normal")

        # Disable widget after text insertion
        self.recommendations_text.config(state='disabled')

    def group_recommendations(self, recs):
        """Helper function to group recommendations and count occurrences"""
        rec_map = {}
        
        # Count occurrences of each recommendation
        for rec in recs:
            # Remove existing "(1 resources)" if present
            rec = re.sub(r'\s*\(1 resources\)\s*$', '', rec.strip())
            rec_map[rec] = rec_map.get(rec, 0) + 1
        
        # Format recommendations with resource count if > 1
        results = []
        for text, count in sorted(rec_map.items()):
            if count > 1:
                results.append(f"{text} ({count} resources)")
            else:
                results.append(text)  # Don't add (1 resources) suffix
        
        return results

def main():
    root = tk.Tk()
    authenticator = None  # Replace with actual authenticator instance
    app = SecurityAnalyzerGUI(root, authenticator)
    root.mainloop()

if __name__ == "__main__":
    main()
