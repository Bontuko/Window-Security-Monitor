#!/usr/bin/env python3
"""
ProcSentinel - Security Dashboard
A modern, attractive security monitoring interface.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.monitors.service_module import scan_services
from app.monitors.task_module import scan_tasks
from app.monitors.wmi_module import scan_wmi
from app.monitors.startup_module import scan_startup
from app.monitors.system_module import scan_system
from app.monitors.network_module import scan_network
from app.monitors.process_module import scan_processes
from app.monitors.registry_module import scan_registry

from app.engines.severity import classify
from app.engines.recommender import generate_explanation_and_recommendation
from app.reporting.exporter import export_all_logs


class ProcSentinelGUI(tk.Tk):
    """Main application window with security dashboard."""
    
    def __init__(self):
        super().__init__()
        
        self.title("🛡️ ProcSentinel - Security Monitor")
        self.geometry("1400x850")
        self.configure(bg="#1a1a2e")
        self.minsize(1200, 700)
        
        self.last_scan_data = []
        self.scanning = False
        
        self._build_ui()
    
    def _build_ui(self):
        """Build the UI."""
        
        # ========== Header ==========
        header = tk.Frame(self, bg="#16213e", height=80)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        # Title
        title_frame = tk.Frame(header, bg="#16213e")
        title_frame.pack(side="left", padx=20, pady=15)
        
        tk.Label(title_frame, text="🛡️ ProcSentinel", font=("Segoe UI", 24, "bold"),
                bg="#16213e", fg="#e94560").pack(side="left")
        tk.Label(title_frame, text="  Windows Security Monitor", font=("Segoe UI", 12),
                bg="#16213e", fg="#a0a0a0").pack(side="left", padx=(10,0))
        
        # Buttons
        btn_frame = tk.Frame(header, bg="#16213e")
        btn_frame.pack(side="right", padx=20)
        
        scan_btn = tk.Button(btn_frame, text="🔍 FULL SCAN", font=("Segoe UI", 11, "bold"),
                            bg="#e94560", fg="white", padx=20, pady=8,
                            activebackground="#ff6b6b", activeforeground="white",
                            relief="flat", cursor="hand2",
                            command=self.scan_all_modules)
        scan_btn.pack(side="left", padx=5)
        
        export_btn = tk.Button(btn_frame, text="📊 Export", font=("Segoe UI", 10),
                              bg="#0f3460", fg="white", padx=15, pady=8,
                              activebackground="#1a5276", activeforeground="white",
                              relief="flat", cursor="hand2",
                              command=self.export_all)
        export_btn.pack(side="left", padx=5)
        
        # Debug Button
        debug_btn = tk.Button(btn_frame, text="🛠️ Debug Scan", font=("Segoe UI", 10),
                             bg="#4b4b4b", fg="white", padx=15, pady=8,
                             activebackground="#606060", activeforeground="white",
                             relief="flat", cursor="hand2",
                             command=self.debug_scan)
        debug_btn.pack(side="left", padx=5)
        
        # ========== Main Content ==========
        main = tk.Frame(self, bg="#1a1a2e")
        main.pack(fill="both", expand=True, padx=15, pady=10)
        
        # Left sidebar - Scrollable
        sidebar_container = tk.Frame(main, bg="#16213e", width=300)
        sidebar_container.pack(side="left", fill="y", padx=(0, 10))
        sidebar_container.pack_propagate(False)
        
        self.sidebar_canvas = tk.Canvas(sidebar_container, bg="#16213e", highlightthickness=0)
        sidebar_vsb = ttk.Scrollbar(sidebar_container, orient="vertical", command=self.sidebar_canvas.yview)
        self.sidebar_content = tk.Frame(self.sidebar_canvas, bg="#16213e", width=280)
        
        self.sidebar_canvas.create_window((0, 0), window=self.sidebar_content, anchor="nw")
        self.sidebar_canvas.configure(yscrollcommand=sidebar_vsb.set)
        
        sidebar_vsb.pack(side="right", fill="y")
        self.sidebar_canvas.pack(side="left", fill="both", expand=True)
        
        # Handle manual scrolling with mouse wheel
        def _on_mousewheel(event):
            self.sidebar_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            
        def _bind_mousewheel(event):
            self.sidebar_canvas.bind_all("<MouseWheel>", _on_mousewheel)
        def _unbind_mousewheel(event):
            self.sidebar_canvas.unbind_all("<MouseWheel>")
            
        self.sidebar_canvas.bind("<Enter>", _bind_mousewheel)
        self.sidebar_canvas.bind("<Leave>", _unbind_mousewheel)
        
        def _configure_sidebar(event):
            self.sidebar_canvas.configure(scrollregion=self.sidebar_canvas.bbox("all"))
            self.sidebar_canvas.itemconfig(1, width=event.width)
        self.sidebar_canvas.bind("<Configure>", _configure_sidebar)
        
        # Security Score Card
        score_card = tk.Frame(self.sidebar_content, bg="#0f3460", padx=20, pady=20)
        score_card.pack(fill="x", padx=10, pady=10)
        
        tk.Label(score_card, text="SECURITY SCORE", font=("Segoe UI", 10, "bold"),
                bg="#0f3460", fg="#a0a0a0").pack()
        
        self.score_label = tk.Label(score_card, text="--", font=("Segoe UI", 48, "bold"),
                                   bg="#0f3460", fg="#00ff88")
        self.score_label.pack()
        
        self.score_status = tk.Label(score_card, text="Run a scan to check", 
                                    font=("Segoe UI", 11), bg="#0f3460", fg="#808080")
        self.score_status.pack()
        
        # Threat Summary Card
        threat_card = tk.Frame(self.sidebar_content, bg="#0f3460", padx=20, pady=15)
        threat_card.pack(fill="x", padx=10, pady=5)
        
        tk.Label(threat_card, text="THREAT SUMMARY", font=("Segoe UI", 10, "bold"),
                bg="#0f3460", fg="#a0a0a0").pack(pady=(0,10))
        
        counts_frame = tk.Frame(threat_card, bg="#0f3460")
        counts_frame.pack(fill="x")
        
        # High count
        high_frame = tk.Frame(counts_frame, bg="#0f3460")
        high_frame.pack(side="left", expand=True)
        self.high_count = tk.Label(high_frame, text="0", font=("Segoe UI", 28, "bold"),
                                  bg="#0f3460", fg="#ff4757")
        self.high_count.pack()
        tk.Label(high_frame, text="HIGH", font=("Segoe UI", 9), 
                bg="#0f3460", fg="#ff4757").pack()
        
        # Medium count
        med_frame = tk.Frame(counts_frame, bg="#0f3460")
        med_frame.pack(side="left", expand=True)
        self.med_count = tk.Label(med_frame, text="0", font=("Segoe UI", 28, "bold"),
                                 bg="#0f3460", fg="#ffa502")
        self.med_count.pack()
        tk.Label(med_frame, text="MEDIUM", font=("Segoe UI", 9), 
                bg="#0f3460", fg="#ffa502").pack()
        
        # Low count
        low_frame = tk.Frame(counts_frame, bg="#0f3460")
        low_frame.pack(side="left", expand=True)
        self.low_count = tk.Label(low_frame, text="0", font=("Segoe UI", 28, "bold"),
                                 bg="#0f3460", fg="#2ed573")
        self.low_count.pack()
        tk.Label(low_frame, text="LOW", font=("Segoe UI", 9), 
                bg="#0f3460", fg="#2ed573").pack()
        
        # Module Stats Card
        module_card = tk.Frame(self.sidebar_content, bg="#0f3460", padx=15, pady=15)
        module_card.pack(fill="both", expand=True, padx=10, pady=5)
        
        tk.Label(module_card, text="MODULES SCANNED", font=("Segoe UI", 10, "bold"),
                bg="#0f3460", fg="#a0a0a0").pack(anchor="w", pady=(0,10))
        
        self.module_list = tk.Frame(module_card, bg="#0f3460")
        self.module_list.pack(fill="both", expand=True)
        
        # Right content
        content = tk.Frame(main, bg="#1a1a2e")
        content.pack(side="right", fill="both", expand=True)
        
        # Filter bar
        filter_frame = tk.Frame(content, bg="#16213e", height=45)
        filter_frame.pack(fill="x", pady=(0,10))
        filter_frame.pack_propagate(False)
        
        filter_inner = tk.Frame(filter_frame, bg="#16213e")
        filter_inner.pack(fill="x", padx=15, pady=10)
        
        tk.Label(filter_inner, text="Filter by severity:", font=("Segoe UI", 10),
                bg="#16213e", fg="#a0a0a0").pack(side="left")
        
        self.severity_var = tk.StringVar(value="All")
        for sev, color in [("All", "#ffffff"), ("High", "#ff4757"), 
                          ("Medium", "#ffa502"), ("Low", "#2ed573")]:
            rb = tk.Radiobutton(filter_inner, text=sev, variable=self.severity_var,
                               value=sev, bg="#16213e", fg=color,
                               selectcolor="#0f3460", activebackground="#16213e",
                               activeforeground=color, font=("Segoe UI", 10),
                               command=self._apply_filter)
            rb.pack(side="left", padx=10)
        
        # Results table
        table_frame = tk.Frame(content, bg="#0f3460")
        table_frame.pack(fill="both", expand=True)
        
        # Create treeview with simple styling
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                       background="#0f3460",
                       foreground="white",
                       fieldbackground="#0f3460",
                       rowheight=28,
                       font=("Segoe UI", 10))
        style.configure("Treeview.Heading",
                       background="#16213e",
                       foreground="white",
                       font=("Segoe UI", 10, "bold"))
        style.map("Treeview",
                 background=[("selected", "#e94560")])
        
        cols = ("severity", "module", "name", "status")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        
        self.tree.heading("severity", text="⚠️ Risk Level")
        self.tree.heading("module", text="Module")
        self.tree.heading("name", text="Item Name")
        self.tree.heading("status", text="Status / Details")
        
        self.tree.column("severity", width=120, anchor="center")
        self.tree.column("module", width=100, anchor="center")
        self.tree.column("name", width=200, anchor="w")
        self.tree.column("status", width=400, anchor="w")
        
        self.tree.tag_configure("High", foreground="#ff4757")
        self.tree.tag_configure("Medium", foreground="#ffa502")
        self.tree.tag_configure("Low", foreground="#2ed573")
        
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Geometry management for scrollbars
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)
        
        self.tree.bind("<<TreeviewSelect>>", self.on_row_select)
        
        # Details panel
        details_frame = tk.Frame(content, bg="#16213e", height=160)
        details_frame.pack(fill="x", pady=(10, 0))
        details_frame.pack_propagate(False)
        
        tk.Label(details_frame, text="📋 DETAILS & RECOMMENDATION", 
                font=("Segoe UI", 10, "bold"),
                bg="#16213e", fg="#a0a0a0").pack(anchor="w", padx=15, pady=(10,5))
        
        details_inner = tk.Frame(details_frame, bg="#0f3460")
        details_inner.pack(fill="both", expand=True, padx=15, pady=(0, 10))
        
        self.details_text = tk.Text(details_inner, bg="#0f3460", fg="white",
                                   font=("Consolas", 10), wrap="word",
                                   borderwidth=0, highlightthickness=0)
        
        details_vsb = ttk.Scrollbar(details_inner, orient="vertical", command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=details_vsb.set)
        
        self.details_text.pack(side="left", fill="both", expand=True)
        details_vsb.pack(side="right", fill="y")
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready - Click 'FULL SCAN' to begin")
        status_bar = tk.Label(self, textvariable=self.status_var,
                             font=("Segoe UI", 9), bg="#1a1a2e", fg="#606060", anchor="w")
        status_bar.pack(fill="x", padx=20, pady=5)
    
    def scan_all_modules(self):
        """Scan all security modules."""
        if self.scanning:
            return
        
        self.scanning = True
        self.status_var.set("🔄 Scanning... Please wait")
        self.update()
        
        combined = []
        
        modules = [
            ("Services", scan_services),
            ("Tasks", scan_tasks),
            ("WMI", scan_wmi),
            ("Startup", scan_startup),
            ("System", scan_system),
            ("Network", scan_network),
            ("Process", scan_processes),
            ("Registry", scan_registry),
        ]
        
        print(f"[DEBUG] Starting scan of {len(modules)} modules...")
        
        for name, func in modules:
            self.status_var.set(f"🔄 Scanning {name}...")
            self.update()
            
            try:
                print(f"[DEBUG] Calling {name} module...")
                raw = func()
                print(f"[DEBUG] {name} returned {len(raw)} items.")
                
                if not raw:
                    continue
                    
                for r in raw:
                    try:
                        entry = dict(Module=name, **r)
                        entry.setdefault("timestamp", datetime.now().isoformat())
                        entry.setdefault("path", "")
                        
                        # Use risk_score if available
                        if "risk_score" in r and r["risk_score"] > 0:
                            if r["risk_score"] >= 40:
                                sev = "High"
                            elif r["risk_score"] >= 20:
                                sev = "Medium"
                            else:
                                sev = "Low"
                            expl = entry.get("status", "")
                        else:
                            sev, expl = classify(entry)
                        
                        entry["severity_summary"] = sev
                        entry["explanation"] = expl
                        
                        try:
                            _, rec = generate_explanation_and_recommendation(entry)
                            entry["recommendation"] = rec
                        except Exception as e:
                            print(f"[DEBUG] Recommender failed for an entry in {name}: {e}")
                            entry["recommendation"] = "Review this item manually."
                        
                        combined.append(entry)
                    except Exception as e:
                        print(f"[DEBUG] Error processing an entry in {name}: {e}")
                        continue
                        
            except Exception as e:
                import traceback
                err_msg = f"Error scanning {name}: {str(e)}\n\n{traceback.format_exc()}"
                print(f"[ERROR] {err_msg}")
                messagebox.showerror("Scan Error", err_msg)
                continue
        
        print(f"[DEBUG] Scan complete. Total items: {len(combined)}")
        
        if not combined:
            messagebox.showwarning("Scan Result", "Scan completed but no data was returned from any module.")
        
        self.last_scan_data = combined
        self._display_results(combined)
        self._update_dashboard(combined)
        
        self.scanning = False
        high = sum(1 for e in combined if e.get("severity_summary") == "High")
        self.status_var.set(f"✅ Scan complete: {len(combined)} items, {high} high-risk")
    
    def _display_results(self, data):
        """Display scan results in the table."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Sort by severity
        severity_order = {"High": 0, "Medium": 1, "Low": 2}
        data_sorted = sorted(data, key=lambda x: severity_order.get(x.get("severity_summary", "Low"), 3))
        
        print(f"[DEBUG] Displaying {len(data_sorted)} items")
        
        for e in data_sorted:
            severity = e.get("severity_summary", "Low")
            module = e.get("Module", "")
            name = e.get("name", "")[:50]  # Truncate long names
            status = e.get("status", "")[:80]  # Truncate long status
            
            icon = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")
            
            self.tree.insert("", "end",
                           values=(f"{icon} {severity}", module, name, status),
                           tags=(severity,))
        
        # Force update
        self.tree.update_idletasks()
        print(f"[DEBUG] Treeview children: {len(self.tree.get_children())}")
    
    def _update_dashboard(self, data):
        """Update dashboard with scan results."""
        high = sum(1 for e in data if e.get("severity_summary") == "High")
        medium = sum(1 for e in data if e.get("severity_summary") == "Medium")
        low = sum(1 for e in data if e.get("severity_summary") == "Low")
        
        # Update counts
        self.high_count.config(text=str(high))
        self.med_count.config(text=str(medium))
        self.low_count.config(text=str(low))
        
        # Calculate score (100 - deductions)
        score = max(0, 100 - (high * 15) - (medium * 5) - (low * 1))
        
        # Update score display
        if score >= 80:
            color = "#2ed573"
            status = "System looks secure"
        elif score >= 50:
            color = "#ffa502"
            status = "Some issues detected"
        elif score >= 25:
            color = "#ff7f50"
            status = "Attention needed"
        else:
            color = "#ff4757"
            status = "Critical issues found!"
        
        self.score_label.config(text=str(score), fg=color)
        self.score_status.config(text=status, fg=color)
        
        # Update module list
        for w in self.module_list.winfo_children():
            w.destroy()
        
        module_counts = {}
        for e in data:
            mod = e.get("Module", "Unknown")
            module_counts[mod] = module_counts.get(mod, 0) + 1
        
        for mod, count in sorted(module_counts.items()):
            frame = tk.Frame(self.module_list, bg="#0f3460")
            frame.pack(fill="x", pady=2)
            tk.Label(frame, text=mod, font=("Segoe UI", 10),
                    bg="#0f3460", fg="white").pack(side="left")
            tk.Label(frame, text=f"{count} items", font=("Segoe UI", 9),
                    bg="#0f3460", fg="#808080").pack(side="right")
        
        # Ensure sidebar scrollable area updates
        self.sidebar_canvas.configure(scrollregion=self.sidebar_canvas.bbox("all"))
    
    def _apply_filter(self):
        """Apply severity filter."""
        if not self.last_scan_data:
            return
        
        sev = self.severity_var.get()
        if sev == "All":
            self._display_results(self.last_scan_data)
        else:
            filtered = [e for e in self.last_scan_data if e.get("severity_summary") == sev]
            self._display_results(filtered)
    
    def on_row_select(self, event):
        """Show details for selected item."""
        self.details_text.delete("1.0", tk.END)
        
        sel = self.tree.selection()
        if not sel:
            return
        
        vals = self.tree.item(sel[0])["values"]
        if not vals:
            return
        
        # Find matching entry
        name_from_tree = vals[2]
        module_from_tree = vals[1]
        
        entry = None
        for e in self.last_scan_data:
            if e.get("name", "")[:50] == name_from_tree and e.get("Module") == module_from_tree:
                entry = e
                break
        
        if not entry:
            return
        
        details = f"""Name: {entry.get('name', 'Unknown')}
Path: {entry.get('path', 'N/A')}
Status: {entry.get('status', 'N/A')}
Severity: {entry.get('severity_summary', 'Unknown')}

EXPLANATION:
{entry.get('explanation', 'No explanation available.')}

RECOMMENDATION:
{entry.get('recommendation', 'No recommendation available.')}
"""
        self.details_text.insert("1.0", details)
    
    def export_all(self):
        """Export results to CSV."""
        if not self.last_scan_data:
            messagebox.showinfo("No Data", "Run a scan first.")
            return
        
        try:
            export_all_logs(self.last_scan_data)
            messagebox.showinfo("Export", "Logs exported to 'exported_logs/' folder.")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

    def debug_scan(self):
        """Run a single safe module to verify connectivity."""
        messagebox.showinfo("Debug", "Starting Debug Scan (System Module only)...")
        self.status_var.set("🔄 Debug Scanning...")
        self.update()
        
        try:
            results = scan_system()
            messagebox.showinfo("Debug", f"System Scan returned {len(results)} items.")
            
            combined = []
            for r in results:
                entry = dict(Module="System", **r)
                entry.setdefault("timestamp", datetime.now().isoformat())
                entry.setdefault("path", "")
                sev, expl = classify(entry)
                entry["severity_summary"] = sev
                entry["explanation"] = expl
                entry["recommendation"] = "Debug scan item."
                combined.append(entry)
            
            self.last_scan_data = combined
            self._display_results(combined)
            self._update_dashboard(combined)
            self.status_var.set("✅ Debug Scan complete.")
            
        except Exception as e:
            import traceback
            messagebox.showerror("Debug Error", f"Debug scan failed: {e}\n\n{traceback.format_exc()}")


if __name__ == "__main__":
    app = ProcSentinelGUI()
    app.mainloop()
