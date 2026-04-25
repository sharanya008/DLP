import re
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

try:
    import matplotlib.pyplot as plt
except ModuleNotFoundError:
    plt = None


class DLPCyberRangeApp:
    CREDIT_CARD_REGEX = re.compile(r"\b\d{4}-\d{4}-\d{4}-\d{4}\b")
    EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    PASSWORD_REGEX = re.compile(
        r"\b(?:password|passwd|login)\b\s*(?:is|=|:)\s*([^\s,;]+)", re.IGNORECASE
    )
    CONFIDENTIAL_KEYWORDS = ["salary", "confidential", "internal", "secret"]
    MITRE_MAPPINGS = {
        "Email Exfiltration": "TA0010 - Exfiltration",
        "File Upload": "T1041 - Exfiltration Over C2 Channel / Web Upload",
        "Clipboard Copy": "TA0010 - Exfiltration",
    }
    SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
    SEVERITY_COLORS = {
        "Low": "#f1c40f",
        "Medium": "#f39c12",
        "High": "#e74c3c",
        "Critical": "#8e1b1b",
        "None": "#95a5a6",
    }
    DATA_TYPES = ["All", "Credit Card", "Email", "Password", "Confidential Keyword", "None"]

    def __init__(self, root):
        self.root = root
        self.root.title("DLP Cyber Range Simulator")
        self.root.geometry("1450x900")
        self.root.configure(bg="#eef3f8")

        self.selected_file = None
        self.last_detection = None
        self.last_payload = ""
        self.log_entries = []

        self._configure_styles()
        self._build_ui()

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"), background="#eef3f8")
        style.configure("Heading.TLabel", font=("Segoe UI", 11, "bold"))
        style.configure("Value.TLabel", font=("Segoe UI", 10), padding=4)
        style.configure("Action.TButton", font=("Segoe UI", 10, "bold"), padding=8)
        style.configure("Send.TButton", font=("Segoe UI", 11, "bold"), padding=10)

    def _build_ui(self):
        title = ttk.Label(
            self.root,
            text="Cyber Range Data Loss Prevention Simulator",
            style="Title.TLabel",
        )
        title.pack(pady=(12, 8))

        container = tk.Frame(self.root, bg="#eef3f8")
        container.pack(fill="both", expand=True, padx=12, pady=8)
        container.grid_columnconfigure(0, weight=3)
        container.grid_columnconfigure(1, weight=2)
        container.grid_rowconfigure(0, weight=2)
        container.grid_rowconfigure(1, weight=2)

        self.attack_frame = self._create_section(container, "A) Attack Panel")
        self.attack_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=(0, 8))

        self.logs_frame = self._create_section(container, "B) Logs Panel")
        self.logs_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 8))

        self.alert_frame = self._create_section(container, "C) Detection & Alert Panel")
        self.alert_frame.grid(row=0, column=1, sticky="nsew", pady=(0, 8))

        self.response_frame = self._create_section(container, "D) Response Panel")
        self.response_frame.grid(row=1, column=1, sticky="nsew")

        self._build_attack_panel()
        self._build_logs_panel()
        self._build_alert_panel()
        self._build_response_panel()

    def _create_section(self, parent, title):
        frame = tk.LabelFrame(
            parent,
            text=title,
            font=("Segoe UI", 11, "bold"),
            bg="#ffffff",
            bd=2,
            relief="groove",
            padx=10,
            pady=10,
        )
        return frame

    def _build_attack_panel(self):
        self.attack_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(self.attack_frame, text="Attack Type", style="Heading.TLabel").grid(
            row=0, column=0, sticky="w", pady=6
        )
        self.attack_type_var = tk.StringVar(value="Email Exfiltration")
        attack_options = ["Email Exfiltration", "File Upload", "Clipboard Copy"]
        ttk.OptionMenu(
            self.attack_frame, self.attack_type_var, self.attack_type_var.get(), *attack_options
        ).grid(row=0, column=1, sticky="ew", pady=6)

        ttk.Label(self.attack_frame, text="User Role", style="Heading.TLabel").grid(
            row=1, column=0, sticky="w", pady=6
        )
        self.user_role_var = tk.StringVar(value="Employee")
        role_options = ["Admin", "Employee", "Guest"]
        ttk.OptionMenu(
            self.attack_frame, self.user_role_var, self.user_role_var.get(), *role_options
        ).grid(row=1, column=1, sticky="ew", pady=6)

        ttk.Label(self.attack_frame, text="Outgoing Content", style="Heading.TLabel").grid(
            row=2, column=0, sticky="nw", pady=6
        )
        self.content_text = ScrolledText(
            self.attack_frame, wrap="word", width=60, height=14, font=("Consolas", 10)
        )
        self.content_text.grid(row=2, column=1, sticky="nsew", pady=6)
        self.content_text.insert(
            "1.0",
            "Try examples like:\n"
            "password = Winter2026!\n"
            "Card: 1234-5678-9012-3456\n"
            "Email: user@example.com\n"
            "This file is confidential and internal.",
        )

        file_row = tk.Frame(self.attack_frame, bg="#ffffff")
        file_row.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 6))
        file_row.grid_columnconfigure(1, weight=1)

        ttk.Button(file_row, text="Upload .txt/.csv", command=self.choose_file).grid(
            row=0, column=0, padx=(0, 8)
        )
        self.file_label_var = tk.StringVar(value="No file selected")
        tk.Label(
            file_row,
            textvariable=self.file_label_var,
            bg="#ffffff",
            fg="#34495e",
            anchor="w",
        ).grid(row=0, column=1, sticky="ew")

        controls_row = tk.Frame(self.attack_frame, bg="#ffffff")
        controls_row.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        controls_row.grid_columnconfigure(0, weight=1)
        controls_row.grid_columnconfigure(1, weight=1)

        ttk.Button(
            controls_row,
            text="Send Data",
            style="Send.TButton",
            command=self.process_attack,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ttk.Button(
            controls_row,
            text="Show Analytics",
            style="Action.TButton",
            command=self.show_analytics,
        ).grid(row=0, column=1, sticky="ew", padx=(6, 0))

        self.attack_frame.grid_rowconfigure(2, weight=1)

    def _build_logs_panel(self):
        filter_frame = tk.Frame(self.logs_frame, bg="#ffffff")
        filter_frame.pack(fill="x", pady=(0, 8))

        ttk.Label(filter_frame, text="Filter Severity", style="Heading.TLabel").grid(
            row=0, column=0, sticky="w", padx=(0, 6)
        )
        self.filter_severity_var = tk.StringVar(value="All")
        ttk.OptionMenu(
            filter_frame,
            self.filter_severity_var,
            "All",
            "All",
            *self.SEVERITY_LEVELS,
            command=lambda _value: self.refresh_logs(),
        ).grid(row=0, column=1, padx=(0, 14))

        ttk.Label(filter_frame, text="Filter Data Type", style="Heading.TLabel").grid(
            row=0, column=2, sticky="w", padx=(0, 6)
        )
        self.filter_data_type_var = tk.StringVar(value="All")
        ttk.OptionMenu(
            filter_frame,
            self.filter_data_type_var,
            "All",
            *self.DATA_TYPES,
            command=lambda _value: self.refresh_logs(),
        ).grid(row=0, column=3, padx=(0, 14))

        ttk.Button(
            filter_frame, text="Clear Filters", command=self.clear_filters
        ).grid(row=0, column=4)

        columns = ("timestamp", "role", "attack", "data_type", "severity", "result", "action")
        self.logs_tree = ttk.Treeview(self.logs_frame, columns=columns, show="headings", height=18)
        headings = {
            "timestamp": "Timestamp",
            "role": "User Role",
            "attack": "Action Type",
            "data_type": "Data Type",
            "severity": "Severity",
            "result": "Detection Result",
            "action": "Action Taken",
        }
        widths = {
            "timestamp": 145,
            "role": 90,
            "attack": 140,
            "data_type": 130,
            "severity": 90,
            "result": 270,
            "action": 140,
        }
        for col in columns:
            self.logs_tree.heading(col, text=headings[col])
            self.logs_tree.column(col, width=widths[col], anchor="center")

        scrollbar = ttk.Scrollbar(self.logs_frame, orient="vertical", command=self.logs_tree.yview)
        self.logs_tree.configure(yscrollcommand=scrollbar.set)
        self.logs_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _build_alert_panel(self):
        self.alert_banner = tk.Label(
            self.alert_frame,
            text="No alert generated yet.",
            bg="#d5dbdb",
            fg="#1f2d3d",
            font=("Segoe UI", 12, "bold"),
            padx=12,
            pady=12,
            wraplength=420,
            justify="left",
        )
        self.alert_banner.pack(fill="x", pady=(0, 10))

        details = tk.Frame(self.alert_frame, bg="#ffffff")
        details.pack(fill="both", expand=True)
        details.grid_columnconfigure(1, weight=1)

        self.detected_type_var = tk.StringVar(value="None")
        self.rule_var = tk.StringVar(value="No rule triggered")
        self.severity_var = tk.StringVar(value="None")
        self.attack_var = tk.StringVar(value="N/A")
        self.role_var = tk.StringVar(value="N/A")
        self.mitre_var = tk.StringVar(value="N/A")
        self.preview_var = tk.StringVar(value="No data processed.")

        fields = [
            ("Detected Data Type", self.detected_type_var),
            ("Rule Triggered", self.rule_var),
            ("Severity", self.severity_var),
            ("Attack Type", self.attack_var),
            ("User Role", self.role_var),
            ("MITRE ATT&CK", self.mitre_var),
            ("Alert Preview", self.preview_var),
        ]
        for idx, (label_text, variable) in enumerate(fields):
            ttk.Label(details, text=label_text, style="Heading.TLabel").grid(
                row=idx, column=0, sticky="nw", pady=5, padx=(0, 8)
            )
            label = tk.Label(
                details,
                textvariable=variable,
                bg="#f8f9f9",
                relief="solid",
                bd=1,
                anchor="w",
                justify="left",
                wraplength=280,
                padx=8,
                pady=6,
            )
            label.grid(row=idx, column=1, sticky="ew", pady=5)

    def _build_response_panel(self):
        info = tk.Label(
            self.response_frame,
            text="Choose a response after a detection event. The final action and any masking result will appear below.",
            bg="#ffffff",
            justify="left",
            wraplength=420,
            anchor="w",
        )
        info.pack(fill="x", pady=(0, 12))

        button_row = tk.Frame(self.response_frame, bg="#ffffff")
        button_row.pack(fill="x", pady=(0, 12))
        for action in ("Block", "Mask", "Allow"):
            ttk.Button(
                button_row,
                text=action,
                style="Action.TButton",
                command=lambda selected=action: self.handle_response(selected),
            ).pack(side="left", padx=6)

        self.response_result_var = tk.StringVar(value="No action taken yet.")
        self.masked_output_var = tk.StringVar(value="Masked output will appear here if used.")

        ttk.Label(self.response_frame, text="Final Action", style="Heading.TLabel").pack(anchor="w")
        tk.Label(
            self.response_frame,
            textvariable=self.response_result_var,
            bg="#ecf0f1",
            anchor="w",
            justify="left",
            padx=10,
            pady=10,
            wraplength=420,
        ).pack(fill="x", pady=(0, 10))

        ttk.Label(self.response_frame, text="Response Output", style="Heading.TLabel").pack(anchor="w")
        tk.Label(
            self.response_frame,
            textvariable=self.masked_output_var,
            bg="#f8f9f9",
            anchor="w",
            justify="left",
            padx=10,
            pady=10,
            wraplength=420,
        ).pack(fill="both", expand=True)

    def choose_file(self):
        file_path = filedialog.askopenfilename(
            title="Select file for DLP scan",
            filetypes=[("Text and CSV Files", "*.txt *.csv"), ("All Files", "*.*")],
        )
        if file_path:
            self.selected_file = file_path
            self.file_label_var.set(file_path)

    def process_attack(self):
        attack_type = self.attack_type_var.get()
        user_role = self.user_role_var.get()
        text_content = self.content_text.get("1.0", "end").strip()

        if attack_type == "File Upload" and not self.selected_file and not text_content:
            messagebox.showwarning(
                "Missing Input", "Select a file or enter content before simulating a file upload."
            )
            return

        if attack_type != "File Upload" and not text_content:
            messagebox.showwarning("Missing Input", "Enter outgoing content before sending data.")
            return

        payload = text_content
        file_detection = None
        if self.selected_file:
            try:
                file_detection = self.scan_file(self.selected_file)
                payload = f"{text_content}\n{file_detection['text']}".strip()
            except OSError as exc:
                messagebox.showerror("File Error", f"Unable to read file:\n{exc}")
                return

        detection = self.detect_sensitive_data(payload)
        if file_detection and file_detection["findings"]:
            detection = self._merge_detections(detection, file_detection)

        detection["attack_type"] = attack_type
        detection["user_role"] = user_role
        detection["severity"] = self.calculate_severity(detection["primary_type"], user_role)

        alert_text = self.generate_alert(detection)
        self.last_detection = detection
        self.last_payload = payload

        self.update_alert_panel(detection, alert_text)
        result_text = "Violation detected" if detection["findings"] else "No sensitive data detected"
        self.response_result_var.set("Awaiting analyst response.")
        self.masked_output_var.set("Select Block, Mask, or Allow.")

        self.log_event(
            user_role=user_role,
            attack_type=attack_type,
            detection_result=result_text,
            data_type=detection["primary_type"],
            severity=detection["severity"],
            action_taken="Pending",
        )

    def detect_sensitive_data(self, text):
        findings = []

        for match in self.CREDIT_CARD_REGEX.finditer(text):
            findings.append(
                {
                    "type": "Credit Card",
                    "rule": "Regex Match - Credit Card Pattern",
                    "match": match.group(),
                    "position": match.span(),
                }
            )

        for match in self.EMAIL_REGEX.finditer(text):
            findings.append(
                {
                    "type": "Email",
                    "rule": "Regex Match - Email Address Pattern",
                    "match": match.group(),
                    "position": match.span(),
                }
            )

        findings.extend(self.apply_context_rules(text))

        lowered = text.lower()
        for keyword in self.CONFIDENTIAL_KEYWORDS:
            if keyword in lowered:
                findings.append(
                    {
                        "type": "Confidential Keyword",
                        "rule": f"Keyword Match - {keyword}",
                        "match": keyword,
                        "position": None,
                    }
                )

        findings = self._deduplicate_findings(findings)
        primary_finding = self._pick_primary_finding(findings)

        return {
            "text": text,
            "findings": findings,
            "primary_type": primary_finding["type"] if primary_finding else "None",
            "primary_rule": primary_finding["rule"] if primary_finding else "No rule triggered",
        }

    def apply_context_rules(self, text):
        context_findings = []
        for match in self.PASSWORD_REGEX.finditer(text):
            context_findings.append(
                {
                    "type": "Password",
                    "rule": "Context Rule - Password keyword with assignment context",
                    "match": match.group(1),
                    "position": match.span(),
                }
            )
        return context_findings

    def scan_file(self, file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file_obj:
            content = file_obj.read()
        detection = self.detect_sensitive_data(content)
        detection["source"] = "file"
        return detection

    def calculate_severity(self, data_type, role):
        base_map = {
            "Credit Card": 2,
            "Password": 2,
            "Email": 1,
            "Confidential Keyword": 0,
            "None": -1,
        }
        score = base_map.get(data_type, 0)
        if role == "Employee":
            score += 1
        elif role == "Admin":
            score -= 1

        score = max(0, min(score, len(self.SEVERITY_LEVELS) - 1))
        return self.SEVERITY_LEVELS[score] if data_type != "None" else "None"

    def generate_alert(self, detection):
        if not detection["findings"]:
            return "No DLP violation detected."

        severity = detection["severity"].upper()
        data_type = detection["primary_type"]
        attack_type = detection["attack_type"]
        role = detection["user_role"]
        rule = detection["primary_rule"]
        mitre = self.MITRE_MAPPINGS.get(attack_type, "N/A")
        return (
            f"[{severity}] DLP Violation - {data_type} Detected\n"
            f"Rule: {rule}\n"
            f"Attack Type: {attack_type}\n"
            f"User Role: {role}\n"
            f"MITRE ATT&CK: {mitre}"
        )

    def handle_response(self, action):
        if not self.last_detection:
            messagebox.showinfo("No Event", "Run an attack simulation before selecting a response.")
            return

        detection = self.last_detection
        final_message = ""
        output_message = ""

        if action == "Block":
            final_message = "Transmission Blocked"
            output_message = "Outbound transmission was denied by the DLP policy engine."
        elif action == "Mask":
            final_message = "Sensitive content masked and transmission sanitized"
            output_message = self.mask_data(self.last_payload, detection["findings"])
        elif action == "Allow":
            final_message = "Data Allowed"
            output_message = "Transmission allowed and logged for audit review."

        self.response_result_var.set(final_message)
        self.masked_output_var.set(output_message)
        self._update_latest_log_action(action)

    def mask_data(self, data, findings):
        masked = data
        for finding in findings:
            match_text = finding["match"]
            if finding["type"] == "Credit Card":
                masked_value = self._mask_credit_card(match_text)
            elif finding["type"] == "Email":
                masked_value = self._mask_email(match_text)
            elif finding["type"] == "Password":
                masked_value = "******"
            elif finding["type"] == "Confidential Keyword":
                masked_value = "[REDACTED]"
            else:
                masked_value = "[MASKED]"

            masked = masked.replace(match_text, masked_value)
        return masked

    def log_event(self, user_role, attack_type, detection_result, data_type, severity, action_taken):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "timestamp": timestamp,
            "role": user_role,
            "attack": attack_type,
            "data_type": data_type,
            "severity": severity,
            "result": detection_result,
            "action": action_taken,
        }
        self.log_entries.append(entry)
        self.refresh_logs()

    def refresh_logs(self):
        for item in self.logs_tree.get_children():
            self.logs_tree.delete(item)

        severity_filter = self.filter_severity_var.get()
        data_type_filter = self.filter_data_type_var.get()

        for entry in self.log_entries:
            if severity_filter != "All" and entry["severity"] != severity_filter:
                continue
            if data_type_filter != "All" and entry["data_type"] != data_type_filter:
                continue

            self.logs_tree.insert(
                "",
                "end",
                values=(
                    entry["timestamp"],
                    entry["role"],
                    entry["attack"],
                    entry["data_type"],
                    entry["severity"],
                    entry["result"],
                    entry["action"],
                ),
            )

    def clear_filters(self):
        self.filter_severity_var.set("All")
        self.filter_data_type_var.set("All")
        self.refresh_logs()

    def show_analytics(self):
        if plt is None:
            messagebox.showwarning(
                "Analytics Unavailable",
                "matplotlib is not installed, so charts cannot be displayed.\n\n"
                "Install it with: pip install matplotlib",
            )
            return

        total_requests = len(self.log_entries)
        total_violations = sum(1 for entry in self.log_entries if entry["data_type"] != "None")
        severity_counts = {level: 0 for level in self.SEVERITY_LEVELS}
        for entry in self.log_entries:
            if entry["severity"] in severity_counts:
                severity_counts[entry["severity"]] += 1

        fig, axes = plt.subplots(1, 2, figsize=(12, 5))
        axes[0].bar(
            ["Total Requests", "Violations"],
            [total_requests, total_violations],
            color=["#5dade2", "#ec7063"],
        )
        axes[0].set_title("Total Requests vs Violations")
        axes[0].set_ylabel("Count")

        non_zero_labels = [label for label, count in severity_counts.items() if count > 0]
        non_zero_values = [count for count in severity_counts.values() if count > 0]
        if non_zero_values:
            colors = [self.SEVERITY_COLORS[label] for label in non_zero_labels]
            axes[1].pie(
                non_zero_values,
                labels=non_zero_labels,
                autopct="%1.1f%%",
                colors=colors,
                startangle=90,
            )
            axes[1].set_title("Severity Distribution")
        else:
            axes[1].text(0.5, 0.5, "No violations yet", ha="center", va="center", fontsize=12)
            axes[1].set_title("Severity Distribution")
            axes[1].axis("off")

        plt.tight_layout()
        plt.show()

    def update_alert_panel(self, detection, alert_text):
        severity = detection["severity"]
        color = self.SEVERITY_COLORS.get(severity, self.SEVERITY_COLORS["None"])
        self.alert_banner.config(text=alert_text, bg=color, fg="#ffffff" if severity in {"High", "Critical"} else "#1f2d3d")

        preview = ", ".join(finding["match"] for finding in detection["findings"][:3]) or "No notable payload"
        self.detected_type_var.set(detection["primary_type"])
        self.rule_var.set(detection["primary_rule"])
        self.severity_var.set(severity)
        self.attack_var.set(detection["attack_type"])
        self.role_var.set(detection["user_role"])
        self.mitre_var.set(self.MITRE_MAPPINGS.get(detection["attack_type"], "N/A"))
        self.preview_var.set(preview[:200])

    def _mask_credit_card(self, value):
        digits = value.split("-")
        return f"--****-{digits[-1]}" if len(digits) == 4 else "--****"

    def _mask_email(self, value):
        if "@" not in value:
            return "su***@masked.local"
        local_part, domain = value.split("@", 1)
        visible = local_part[:2] if len(local_part) >= 2 else local_part[:1]
        return f"{visible}***@{domain}"

    def _deduplicate_findings(self, findings):
        seen = set()
        unique_findings = []
        for finding in findings:
            key = (finding["type"], finding["rule"], finding["match"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        return unique_findings

    def _pick_primary_finding(self, findings):
        if not findings:
            return None
        priority = {
            "Credit Card": 4,
            "Password": 3,
            "Email": 2,
            "Confidential Keyword": 1,
        }
        return max(findings, key=lambda item: priority.get(item["type"], 0))

    def _merge_detections(self, primary_detection, file_detection):
        merged_findings = primary_detection["findings"] + file_detection["findings"]
        merged_findings = self._deduplicate_findings(merged_findings)
        primary_finding = self._pick_primary_finding(merged_findings)
        return {
            "text": primary_detection["text"],
            "findings": merged_findings,
            "primary_type": primary_finding["type"] if primary_finding else "None",
            "primary_rule": primary_finding["rule"] if primary_finding else "No rule triggered",
        }

    def _update_latest_log_action(self, action):
        if not self.log_entries:
            return
        latest = self.log_entries[-1]
        latest["action"] = action
        self.refresh_logs()


def main():
    root = tk.Tk()
    app = DLPCyberRangeApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
