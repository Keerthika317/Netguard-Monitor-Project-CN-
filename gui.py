#!/usr/bin/env python3
import gi
gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
from gi.repository import Gtk, Gdk, GLib, Pango
import json
import subprocess
import threading
import queue
import time
import os
import signal
import random
from datetime import datetime

class NetworkMonitorGUI:
    def __init__(self):
        # Create main window
        self.window = Gtk.Window(title="Network Monitor")
        self.window.set_default_size(1000, 800)
        self.window.set_border_width(10)

        # Main container
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.window.add(main_box)

        # Header
        header_label = Gtk.Label()
        header_label.set_markup("<span size='x-large' weight='bold'>Real-Time Network Monitor</span>")
        main_box.pack_start(header_label, False, False, 0)

        # Alert Panel
        alert_frame = Gtk.Frame(label="Network Alerts")
        main_box.pack_start(alert_frame, False, False, 0)

        alert_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        alert_box.set_margin_top(10)
        alert_box.set_margin_bottom(10)
        alert_box.set_margin_start(10)
        alert_box.set_margin_end(10)
        alert_frame.add(alert_box)

        self.alert_label = Gtk.Label(label="No alerts currently")
        self.alert_label.set_halign(Gtk.Align.START)
        alert_box.pack_start(self.alert_label, False, False, 0)

        # Control Panel
        control_frame = Gtk.Frame(label="Control Panel")
        main_box.pack_start(control_frame, False, False, 0)

        control_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        control_box.set_margin_top(10)
        control_box.set_margin_bottom(10)
        control_box.set_margin_start(10)
        control_box.set_margin_end(10)
        control_frame.add(control_box)

        self.start_button = Gtk.Button(label="Start Monitoring")
        self.start_button.connect("clicked", self.on_start_button_clicked)
        control_box.pack_start(self.start_button, False, False, 0)

        self.stop_button = Gtk.Button(label="Stop Monitoring")
        self.stop_button.connect("clicked", self.on_stop_button_clicked)
        self.stop_button.set_sensitive(False)
        control_box.pack_start(self.stop_button, False, False, 0)

        self.report_button = Gtk.Button(label="Generate Report")
        self.report_button.connect("clicked", self.on_report_button_clicked)
        control_box.pack_start(self.report_button, False, False, 0)

        # Settings Panel
        settings_frame = Gtk.Frame(label="Monitoring Settings")
        main_box.pack_start(settings_frame, False, False, 0)

        settings_grid = Gtk.Grid()
        settings_grid.set_margin_top(10)
        settings_grid.set_margin_bottom(10)
        settings_grid.set_margin_start(10)
        settings_grid.set_margin_end(10)
        settings_grid.set_column_spacing(10)
        settings_grid.set_row_spacing(10)
        settings_frame.add(settings_grid)

        # Target Host
        target_host_label = Gtk.Label(label="Target Host:")
        target_host_label.set_halign(Gtk.Align.START)
        settings_grid.attach(target_host_label, 0, 0, 1, 1)

        self.target_host_entry = Gtk.Entry()
        self.target_host_entry.set_text("google.com")
        settings_grid.attach(self.target_host_entry, 1, 0, 1, 1)

        # Latency Threshold
        latency_threshold_label = Gtk.Label(label="Latency Threshold (ms):")
        latency_threshold_label.set_halign(Gtk.Align.START)
        settings_grid.attach(latency_threshold_label, 0, 1, 1, 1)

        self.latency_threshold_entry = Gtk.Entry()
        self.latency_threshold_entry.set_text("100")
        settings_grid.attach(self.latency_threshold_entry, 1, 1, 1, 1)

        # Packet Loss Threshold
        packet_loss_threshold_label = Gtk.Label(label="Packet Loss Threshold (%):")
        packet_loss_threshold_label.set_halign(Gtk.Align.START)
        settings_grid.attach(packet_loss_threshold_label, 0, 2, 1, 1)

        self.packet_loss_threshold_entry = Gtk.Entry()
        self.packet_loss_threshold_entry.set_text("5")
        settings_grid.attach(self.packet_loss_threshold_entry, 1, 2, 1, 1)

        # Bandwidth Threshold
        bandwidth_threshold_label = Gtk.Label(label="Low Bandwidth Threshold (KB/s):")
        bandwidth_threshold_label.set_halign(Gtk.Align.START)
        settings_grid.attach(bandwidth_threshold_label, 0, 3, 1, 1)

        self.bandwidth_threshold_entry = Gtk.Entry()
        self.bandwidth_threshold_entry.set_text("50")
        settings_grid.attach(self.bandwidth_threshold_entry, 1, 3, 1, 1)

        # Stats Display
        stats_frame = Gtk.Frame(label="Real-Time Statistics")
        main_box.pack_start(stats_frame, False, False, 0)

        stats_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        stats_box.set_margin_top(10)
        stats_box.set_margin_bottom(10)
        stats_box.set_margin_start(10)
        stats_box.set_margin_end(10)
        stats_frame.add(stats_box)

        # Left stats
        left_stats = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        stats_box.pack_start(left_stats, True, True, 0)

        self.total_usage_label = Gtk.Label(label="Total Usage: 0 bytes")
        self.total_usage_label.set_halign(Gtk.Align.START)
        left_stats.pack_start(self.total_usage_label, False, False, 0)

        self.browser_count_label = Gtk.Label(label="Browsers Detected: 0")
        self.browser_count_label.set_halign(Gtk.Align.START)
        left_stats.pack_start(self.browser_count_label, False, False, 0)

        # Center stats
        center_stats = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        stats_box.pack_start(center_stats, True, True, 0)

        self.bandwidth_label = Gtk.Label(label="Current Bandwidth: 0 KB/s")
        self.bandwidth_label.set_halign(Gtk.Align.START)
        center_stats.pack_start(self.bandwidth_label, False, False, 0)

        self.connection_quality_label = Gtk.Label(label="Connection Quality: Unknown")
        self.connection_quality_label.set_halign(Gtk.Align.START)
        center_stats.pack_start(self.connection_quality_label, False, False, 0)

        # Right stats
        right_stats = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        stats_box.pack_start(right_stats, True, True, 0)

        self.latency_label = Gtk.Label(label="Latency: -- ms")
        self.latency_label.set_halign(Gtk.Align.START)
        right_stats.pack_start(self.latency_label, False, False, 0)

        self.packet_loss_label = Gtk.Label(label="Packet Loss: --%")
        self.packet_loss_label.set_halign(Gtk.Align.START)
        right_stats.pack_start(self.packet_loss_label, False, False, 0)

        # Notebook for detailed views
        self.notebook = Gtk.Notebook()
        self.notebook.set_margin_top(10)
        main_box.pack_start(self.notebook, True, True, 0)

        # Network Traffic Tab
        network_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        network_scrolled = Gtk.ScrolledWindow()
        network_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        # Network traffic treeview
        network_store = Gtk.ListStore(str, str, str)
        self.network_tree = Gtk.TreeView(model=network_store)

        renderer = Gtk.CellRendererText()

        columns = [
            ("Protocol", 0),
            ("Bytes", 1),
            ("Percentage", 2)
        ]

        for i, (title, col_id) in enumerate(columns):
            column = Gtk.TreeViewColumn(title, renderer, text=col_id)
            column.set_resizable(True)
            self.network_tree.append_column(column)

        network_scrolled.add(self.network_tree)
        network_box.pack_start(network_scrolled, True, True, 0)
        self.notebook.append_page(network_box, Gtk.Label(label="Network Traffic"))

        # Browser Usage Tab
        browser_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        browser_scrolled = Gtk.ScrolledWindow()
        browser_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        # Browser usage treeview
        browser_store = Gtk.ListStore(str, str, str, str)
        self.browser_tree = Gtk.TreeView(model=browser_store)

        browser_columns = [
            ("Browser", 0),
            ("Incoming (bytes)", 1),
            ("Outgoing (bytes)", 2),
            ("Total (bytes)", 3)
        ]

        for i, (title, col_id) in enumerate(browser_columns):
            column = Gtk.TreeViewColumn(title, renderer, text=col_id)
            column.set_resizable(True)
            self.browser_tree.append_column(column)

        browser_scrolled.add(self.browser_tree)
        browser_box.pack_start(browser_scrolled, True, True, 0)
        self.notebook.append_page(browser_box, Gtk.Label(label="Browser Usage"))

        # Console Output Tab
        console_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        console_scrolled = Gtk.ScrolledWindow()
        console_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        self.console_text = Gtk.TextView()
        self.console_text.set_editable(False)
        self.console_text.set_wrap_mode(Gtk.WrapMode.WORD)

        console_scrolled.add(self.console_text)
        console_box.pack_start(console_scrolled, True, True, 0)
        self.notebook.append_page(console_box, Gtk.Label(label="Console Output"))

        # Initialize data structures
        self.monitor_process = None
        self.data_queue = queue.Queue()
        self.is_monitoring = False
        self.console_buffer = self.console_text.get_buffer()
        self.last_demo_update = 0
        self.demo_mode = False
        self.alerts = []
        self.last_total_bytes = 0
        self.last_update_time = time.time()
        self.current_bandwidth = 0

        # Apply styling
        self.apply_styling()

        # Connect signals
        self.window.connect("destroy", self.on_main_window_destroy)

        # Console header
        self.console_buffer.insert(self.console_buffer.get_end_iter(),
                                 "=== Network Monitor Console ===\n")
        self.console_buffer.insert(self.console_buffer.get_end_iter(),
                                 "Start monitoring to see real-time data...\n\n")

    def apply_styling(self):
        css = """
        .window-style {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }

        .header-style {
            color: white;
            padding: 10px;
        }

        .frame-style {
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.95);
        }

        .button-style {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 16px;
            font-weight: bold;
        }

        .button-style:hover {
            background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
        }

        .stats-style {
            background: rgba(255, 255, 255, 0.9);
            padding: 8px;
            border-radius: 4px;
            font-weight: bold;
        }

        .alert-style {
            color: red;
            font-weight: bold;
        }

        .alert-normal {
            color: green;
            font-weight: bold;
        }

        .alert-warning {
            color: orange;
            font-weight: bold;
        }

        .alert-critical {
            color: red;
            font-weight: bold;
        }
        """

        style_provider = Gtk.CssProvider()
        style_provider.load_from_data(css.encode())

        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(),
            style_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

        # Apply CSS classes
        self.window.get_style_context().add_class("window-style")
        self.start_button.get_style_context().add_class("button-style")
        self.stop_button.get_style_context().add_class("button-style")
        self.report_button.get_style_context().add_class("button-style")

    def on_start_button_clicked(self, button):
        if not self.is_monitoring:
            self.start_monitoring()

    def on_stop_button_clicked(self, button):
        if self.is_monitoring:
            self.stop_monitoring()

    def on_report_button_clicked(self, button):
        self.generate_report()

    def start_monitoring(self):
        try:
            # Compile C code if not already compiled
            if not os.path.exists("network_monitor"):
                self.console_print("Compiling C backend...")
                result = subprocess.run(["gcc", "-o", "network_monitor", "network_monitor.c",
                                      "-lpcap", "-ljson-c"],
                                     capture_output=True, text=True)
                if result.returncode != 0:
                    self.console_print(f"Compilation failed: {result.stderr}")
                    self.show_alert("Compilation Error", f"Failed to compile C backend:\n{result.stderr}")
                    return

            self.console_print("Starting network monitoring...")

            # Start the C monitor process
            self.monitor_process = subprocess.Popen(
                ["./network_monitor"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            self.is_monitoring = True
            self.demo_mode = False
            self.start_button.set_sensitive(False)
            self.stop_button.set_sensitive(True)
            self.alerts = []

            # Start thread to read data from C process
            self.monitor_thread = threading.Thread(target=self.read_monitor_data)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()

            # Start thread to read stderr
            self.stderr_thread = threading.Thread(target=self.read_stderr)
            self.stderr_thread.daemon = True
            self.stderr_thread.start()

            # Start GUI update timer
            GLib.timeout_add(1000, self.update_gui)

            self.console_print("Monitoring started successfully!")
            self.console_print("Generating traffic in Firefox/Chrome to see real data...")
            self.show_alert("Monitoring Started", "Network monitoring has been started successfully.\n\nOpen Firefox or Chrome to see browser traffic detection.")

        except Exception as e:
            error_msg = f"Failed to start monitoring: {str(e)}"
            self.console_print(f"ERROR: {error_msg}")
            self.show_alert("Error", error_msg)

    def stop_monitoring(self):
        if self.monitor_process:
            self.console_print("Stopping monitoring...")
            self.monitor_process.terminate()
            try:
                self.monitor_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.monitor_process.kill()

            self.monitor_process = None

        self.is_monitoring = False
        self.demo_mode = False
        self.start_button.set_sensitive(True)
        self.stop_button.set_sensitive(False)

        self.console_print("Monitoring stopped.")
        self.show_alert("Monitoring Stopped", "Network monitoring has been stopped.")

    def read_monitor_data(self):
        while self.is_monitoring and self.monitor_process:
            try:
                line = self.monitor_process.stdout.readline()
                if line:
                    try:
                        data = json.loads(line.strip())
                        self.data_queue.put(data)
                        self.demo_mode = False  # We're getting real data
                    except json.JSONDecodeError as e:
                        if line.strip():  # Only print non-empty lines
                            self.console_print(f"JSON Parse Error: {e}")
                            self.console_print(f"Raw line: {line.strip()}")
            except Exception as e:
                self.console_print(f"Error reading stdout: {e}")
                break

    def read_stderr(self):
        while self.is_monitoring and self.monitor_process:
            try:
                line = self.monitor_process.stderr.readline()
                if line:
                    self.console_print(f"STDERR: {line.strip()}")
            except:
                break

    def update_gui(self):
        # Process all available data from queue
        processed_count = 0
        data_received = False

        while not self.data_queue.empty() and processed_count < 10:
            try:
                data = self.data_queue.get_nowait()
                self.process_monitor_data(data)
                processed_count += 1
                data_received = True
            except queue.Empty:
                break

        # If no data received for a while, show demo data
        if not data_received and self.is_monitoring:
            # Wait a bit before showing demo data to allow real data to come in
            if not hasattr(self, 'monitor_start_time'):
                self.monitor_start_time = time.time()

            if time.time() - self.monitor_start_time > 5:  # Show demo after 5 seconds of no data
                self.demo_mode = True
                self.show_demo_data()

        return self.is_monitoring  # Continue timer if monitoring

    def check_network_quality(self, latency, packet_loss, bandwidth):
        """Check network quality and generate alerts"""
        current_time = datetime.now().strftime("%H:%M:%S")
        new_alerts = []

        try:
            latency_threshold = float(self.latency_threshold_entry.get_text())
            packet_loss_threshold = float(self.packet_loss_threshold_entry.get_text())
            bandwidth_threshold = float(self.bandwidth_threshold_entry.get_text())

            # Check latency
            if latency > latency_threshold:
                alert_msg = f"[{current_time}] High Latency Alert: {latency:.2f}ms (Threshold: {latency_threshold}ms)"
                if alert_msg not in self.alerts:
                    self.alerts.append(alert_msg)
                    new_alerts.append(alert_msg)
                    self.console_print(f"ALERT: {alert_msg}")

            # Check packet loss
            if packet_loss > packet_loss_threshold:
                alert_msg = f"[{current_time}] High Packet Loss Alert: {packet_loss:.1f}% (Threshold: {packet_loss_threshold}%)"
                if alert_msg not in self.alerts:
                    self.alerts.append(alert_msg)
                    new_alerts.append(alert_msg)
                    self.console_print(f"ALERT: {alert_msg}")

            # Check bandwidth
            if bandwidth < bandwidth_threshold and bandwidth > 0:
                alert_msg = f"[{current_time}] Low Bandwidth Alert: {bandwidth:.2f} KB/s (Threshold: {bandwidth_threshold} KB/s)"
                if alert_msg not in self.alerts:
                    self.alerts.append(alert_msg)
                    new_alerts.append(alert_msg)
                    self.console_print(f"ALERT: {alert_msg}")

            # Update connection quality label
            quality_score = 0
            if latency < 50 and packet_loss < 1 and bandwidth > 100:
                quality = "Excellent"
                quality_color = "green"
                quality_score = 5
            elif latency < 100 and packet_loss < 3 and bandwidth > 50:
                quality = "Good"
                quality_color = "blue"
                quality_score = 4
            elif latency < 200 and packet_loss < 5 and bandwidth > 25:
                quality = "Fair"
                quality_color = "orange"
                quality_score = 3
            elif latency < 500 and packet_loss < 10:
                quality = "Poor"
                quality_color = "red"
                quality_score = 2
            else:
                quality = "Very Poor"
                quality_color = "darkred"
                quality_score = 1

            self.connection_quality_label.set_markup(
                f'<span foreground="{quality_color}">Connection Quality: {quality} ({quality_score}/5)</span>'
            )

            # Update alert display
            if new_alerts:
                alert_text = "\n".join(new_alerts[-3:])  # Show last 3 alerts
                self.alert_label.set_markup(f'<span foreground="red" weight="bold">ALERTS:\n{alert_text}</span>')
            elif not self.alerts:
                self.alert_label.set_markup('<span foreground="green">No alerts - Network conditions normal</span>')

        except ValueError:
            pass

    def process_monitor_data(self, data):
        try:
            current_time = time.time()
            time_diff = current_time - self.last_update_time

            # Update network statistics
            network_stats = data.get("network_stats", {})
            total_bytes = network_stats.get("total_bytes", 0)
            incoming_bytes = network_stats.get("incoming_bytes", 0)
            outgoing_bytes = network_stats.get("outgoing_bytes", 0)
            packet_count = network_stats.get("packet_count", 0)

            # Calculate bandwidth
            if time_diff > 0:
                bytes_diff = total_bytes - self.last_total_bytes
                self.current_bandwidth = (bytes_diff / time_diff) / 1024  # KB/s
                self.last_total_bytes = total_bytes
                self.last_update_time = current_time

            self.total_usage_label.set_text(
                f"Total: {self.format_bytes(total_bytes)} | "
                f"In: {self.format_bytes(incoming_bytes)} | "
                f"Out: {self.format_bytes(outgoing_bytes)} | "
                f"Packets: {packet_count}"
            )

            # Update bandwidth label
            self.bandwidth_label.set_text(f"Current Bandwidth: {self.current_bandwidth:.2f} KB/s")

            # Update network traffic treeview
            network_store = self.network_tree.get_model()
            network_store.clear()

            protocols = [
                ("TCP", network_stats.get("tcp_bytes", 0)),
                ("UDP", network_stats.get("udp_bytes", 0)),
                ("ICMP", network_stats.get("icmp_bytes", 0))
            ]

            for protocol, bytes_count in protocols:
                percentage = (bytes_count / total_bytes * 100) if total_bytes > 0 else 0
                network_store.append([protocol, self.format_bytes(bytes_count), f"{percentage:.1f}%"])

            # Update browser statistics
            browser_stats = data.get("browser_stats", [])
            browser_count = data.get("browser_count", 0)

            self.browser_count_label.set_text(f"Browsers Detected: {browser_count}")

            browser_store = self.browser_tree.get_model()
            browser_store.clear()

            for browser in browser_stats:
                incoming = browser.get("incoming_bytes", 0)
                outgoing = browser.get("outgoing_bytes", 0)
                total = incoming + outgoing

                browser_store.append([
                    browser.get("name", "Unknown"),
                    self.format_bytes(incoming),
                    self.format_bytes(outgoing),
                    self.format_bytes(total)
                ])

            # Update latency and packet loss
            ping_stats = data.get("ping_stats", {})
            latency = ping_stats.get("latency", -1)
            packet_loss = ping_stats.get("packet_loss", 0)
            target_host = ping_stats.get("target_host", "google.com")

            if latency >= 0:
                latency_text = f"Latency to {target_host}: {latency:.2f} ms"
                self.latency_label.set_text(latency_text)

                # Check threshold
                try:
                    latency_threshold = float(self.latency_threshold_entry.get_text())
                    if latency > latency_threshold:
                        self.latency_label.set_markup(f'<span foreground="red">{latency_text} (High!)</span>')
                    else:
                        self.latency_label.set_markup(f'<span foreground="green">{latency_text}</span>')
                except ValueError:
                    self.latency_label.set_text(latency_text)
            else:
                self.latency_label.set_text(f"Latency to {target_host}: -- ms")

            packet_loss_text = f"Packet Loss: {packet_loss:.1f}%"
            self.packet_loss_label.set_text(packet_loss_text)

            # Check packet loss threshold
            try:
                packet_loss_threshold = float(self.packet_loss_threshold_entry.get_text())
                if packet_loss > packet_loss_threshold:
                    self.packet_loss_label.set_markup(f'<span foreground="red">{packet_loss_text} (High!)</span>')
                else:
                    self.packet_loss_label.set_markup(f'<span foreground="green">{packet_loss_text}</span>')
            except ValueError:
                self.packet_loss_label.set_text(packet_loss_text)

            # Check network quality and generate alerts
            self.check_network_quality(latency, packet_loss, self.current_bandwidth)

            # Print to console
            if packet_count > 0:
                self.console_print(f"Update: Total={self.format_bytes(total_bytes)}, "
                                 f"Packets={packet_count}, "
                                 f"Browsers={browser_count}, "
                                 f"Latency={latency:.2f}ms, "
                                 f"Loss={packet_loss:.1f}%, "
                                 f"BW={self.current_bandwidth:.2f}KB/s")

        except Exception as e:
            self.console_print(f"Error processing data: {e}")

    def show_demo_data(self):
        """Show demo data when no real data is available"""
        current_time = time.time()

        # Update demo data every 2 seconds
        if current_time - self.last_demo_update >= 2:
            # Simulate network traffic growth
            if not hasattr(self, 'demo_total_bytes'):
                self.demo_total_bytes = 1000000
                self.demo_incoming = 500000
                self.demo_outgoing = 500000
            else:
                # Increment values to show progress
                increment = random.randint(10000, 100000)
                self.demo_total_bytes += increment
                self.demo_incoming += random.randint(5000, 50000)
                self.demo_outgoing += increment - random.randint(5000, 50000)

            # Calculate demo bandwidth
            if not hasattr(self, 'demo_last_total_bytes'):
                self.demo_last_total_bytes = self.demo_total_bytes
                self.demo_last_update_time = current_time
                self.demo_bandwidth = 0
            else:
                time_diff = current_time - self.demo_last_update_time
                if time_diff > 0:
                    bytes_diff = self.demo_total_bytes - self.demo_last_total_bytes
                    self.demo_bandwidth = (bytes_diff / time_diff) / 1024
                    self.demo_last_total_bytes = self.demo_total_bytes
                    self.demo_last_update_time = current_time

            self.total_usage_label.set_text(
                f"Total: {self.format_bytes(self.demo_total_bytes)} | "
                f"In: {self.format_bytes(self.demo_incoming)} | "
                f"Out: {self.format_bytes(self.demo_outgoing)} | "
                f"Packets: {self.demo_total_bytes // 1000}"
            )

            self.bandwidth_label.set_text(f"Current Bandwidth: {self.demo_bandwidth:.2f} KB/s")

            # Update network traffic
            network_store = self.network_tree.get_model()
            network_store.clear()

            protocols = [
                ("TCP", int(self.demo_total_bytes * 0.7)),
                ("UDP", int(self.demo_total_bytes * 0.25)),
                ("ICMP", int(self.demo_total_bytes * 0.05))
            ]

            for protocol, bytes_count in protocols:
                percentage = (bytes_count / self.demo_total_bytes * 100) if self.demo_total_bytes > 0 else 0
                network_store.append([protocol, self.format_bytes(bytes_count), f"{percentage:.1f}%"])

            # Update browser stats
            browser_store = self.browser_tree.get_model()
            browser_store.clear()

            browsers = [
                ("firefox", int(self.demo_incoming * 0.4), int(self.demo_outgoing * 0.3)),
                ("chrome", int(self.demo_incoming * 0.35), int(self.demo_outgoing * 0.4)),
                ("edge", int(self.demo_incoming * 0.25), int(self.demo_outgoing * 0.3))
            ]

            for name, incoming, outgoing in browsers:
                total = incoming + outgoing
                browser_store.append([
                    name,
                    self.format_bytes(incoming),
                    self.format_bytes(outgoing),
                    self.format_bytes(total)
                ])

            self.browser_count_label.set_text(f"Browsers Detected: {len(browsers)}")

            # Update latency with some variation
            latency = random.uniform(15, 45)
            packet_loss = random.uniform(0, 1.5)

            target_host = self.target_host_entry.get_text() or "google.com"

            latency_text = f"Latency to {target_host}: {latency:.2f} ms"
            self.latency_label.set_text(latency_text)
            self.latency_label.set_markup(f'<span foreground="green">{latency_text}</span>')

            packet_loss_text = f"Packet Loss: {packet_loss:.1f}%"
            self.packet_loss_label.set_text(packet_loss_text)
            self.packet_loss_label.set_markup(f'<span foreground="green">{packet_loss_text}</span>')

            # Check network quality for demo data
            self.check_network_quality(latency, packet_loss, self.demo_bandwidth)

            self.connection_quality_label.set_markup('<span foreground="green">Connection Quality: Good (4/5)</span>')

            self.last_demo_update = current_time
            self.console_print("Demo data: Simulating network traffic (open Firefox/Chrome for real data)")

    def format_bytes(self, bytes_count):
        """Format bytes count to human readable format"""
        if bytes_count == 0:
            return "0 B"

        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_count < 1024.0:
                return f"{bytes_count:.2f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.2f} TB"

    def generate_report(self):
        dialog = Gtk.FileChooserDialog(
            title="Save Report",
            parent=self.window,
            action=Gtk.FileChooserAction.SAVE
        )
        dialog.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_SAVE, Gtk.ResponseType.OK
        )
        dialog.set_current_name("network_report.doc")

        response = dialog.run()
        if response == Gtk.ResponseType.OK:
            filename = dialog.get_filename()
            try:
                with open(filename, 'w') as f:
                    f.write("NETWORK MONITORING REPORT\n")
                    f.write("=" * 50 + "\n\n")

                    # Report Header
                    f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Monitoring Duration: {time.time() - getattr(self, 'monitor_start_time', time.time()) :.0f} seconds\n")
                    f.write(f"Data Source: {'DEMO DATA' if self.demo_mode else 'REAL-TIME MONITORING'}\n\n")

                    # Executive Summary
                    f.write("EXECUTIVE SUMMARY\n")
                    f.write("-" * 30 + "\n")

                    # Get current statistics
                    network_store = self.network_tree.get_model()
                    browser_store = self.browser_tree.get_model()

                    total_traffic = getattr(self, 'demo_total_bytes', 0) if self.demo_mode else 0
                    browser_count = len(browser_store) if browser_store else 0

                    f.write(f"Total Network Traffic: {self.total_usage_label.get_text()}\n")
                    f.write(f"Browsers Detected: {browser_count}\n")
                    f.write(f"Current Latency: {self.latency_label.get_text()}\n")
                    f.write(f"Packet Loss: {self.packet_loss_label.get_text()}\n")
                    f.write(f"Current Bandwidth: {self.bandwidth_label.get_text()}\n")
                    f.write(f"Connection Quality: {self.connection_quality_label.get_text()}\n\n")

                    # Network Traffic Analysis
                    f.write("NETWORK TRAFFIC ANALYSIS\n")
                    f.write("-" * 30 + "\n")
                    if network_store:
                        iter = network_store.get_iter_first()
                        while iter:
                            protocol = network_store.get_value(iter, 0)
                            bytes = network_store.get_value(iter, 1)
                            percentage = network_store.get_value(iter, 2)
                            f.write(f"{protocol}: {bytes} ({percentage})\n")
                            iter = network_store.iter_next(iter)
                    f.write("\n")

                    # Browser Usage Analysis
                    f.write("BROWSER USAGE ANALYSIS\n")
                    f.write("-" * 30 + "\n")
                    if browser_store:
                        iter = browser_store.get_iter_first()
                        while iter:
                            browser = browser_store.get_value(iter, 0)
                            incoming = browser_store.get_value(iter, 1)
                            outgoing = browser_store.get_value(iter, 2)
                            total = browser_store.get_value(iter, 3)
                            f.write(f"{browser}:\n")
                            f.write(f"  Incoming: {incoming}\n")
                            f.write(f"  Outgoing: {outgoing}\n")
                            f.write(f"  Total: {total}\n\n")
                            iter = browser_store.iter_next(iter)

                    # Alert History
                    f.write("ALERT HISTORY\n")
                    f.write("-" * 30 + "\n")
                    if self.alerts:
                        for alert in self.alerts:
                            f.write(f"{alert}\n")
                    else:
                        f.write("No alerts generated during monitoring session.\n")
                    f.write("\n")

                    # Monitoring Settings
                    f.write("MONITORING SETTINGS\n")
                    f.write("-" * 30 + "\n")
                    f.write(f"Target Host: {self.target_host_entry.get_text()}\n")
                    f.write(f"Latency Threshold: {self.latency_threshold_entry.get_text()} ms\n")
                    f.write(f"Packet Loss Threshold: {self.packet_loss_threshold_entry.get_text()} %\n")
                    f.write(f"Bandwidth Threshold: {self.bandwidth_threshold_entry.get_text()} KB/s\n\n")

                    # Recommendations
                    f.write("RECOMMENDATIONS\n")
                    f.write("-" * 30 + "\n")
                    if self.alerts:
                        f.write("Based on the alerts generated, consider:\n")
                        if any("High Latency" in alert for alert in self.alerts):
                            f.write("- Check your internet connection speed\n")
                            f.write("- Contact your ISP if latency persists\n")
                            f.write("- Consider using a wired connection instead of WiFi\n")
                        if any("High Packet Loss" in alert for alert in self.alerts):
                            f.write("- Check network cables and connections\n")
                            f.write("- Restart your router/modem\n")
                            f.write("- Avoid network congestion periods\n")
                        if any("Low Bandwidth" in alert for alert in self.alerts):
                            f.write("- Close bandwidth-intensive applications\n")
                            f.write("- Check for background downloads/uploads\n")
                            f.write("- Consider upgrading your internet plan\n")
                    else:
                        f.write("Network performance is within acceptable parameters.\n")
                        f.write("No immediate actions required.\n")

                    f.write("\n" + "=" * 50 + "\n")
                    f.write("End of Report\n")

                self.console_print(f"Comprehensive report saved to: {filename}")
                self.show_alert("Report Generated", f"Comprehensive report saved to: {filename}")
            except Exception as e:
                error_msg = f"Failed to save report: {str(e)}"
                self.console_print(f"ERROR: {error_msg}")
                self.show_alert("Error", error_msg)

        dialog.destroy()

    def console_print(self, message):
        """Add message to console with timestamp"""
        timestamp = time.strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"

        GLib.idle_add(self._add_to_console, formatted_message)

    def _add_to_console(self, message):
        """Thread-safe method to add text to console"""
        end_iter = self.console_buffer.get_end_iter()
        self.console_buffer.insert(end_iter, message)

        # Auto-scroll to bottom
        mark = self.console_buffer.create_mark(None, end_iter, True)
        self.console_text.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)

        # Limit console buffer size to prevent memory issues
        start_iter = self.console_buffer.get_start_iter()
        line_count = self.console_buffer.get_line_count()
        if line_count > 1000:
            end_iter = self.console_buffer.get_iter_at_line(500)
            self.console_buffer.delete(start_iter, end_iter)

        return False

    def show_alert(self, title, message):
        dialog = Gtk.MessageDialog(
            transient_for=self.window,
            flags=0,
            message_type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.OK,
            text=title
        )
        dialog.format_secondary_text(message)
        dialog.run()
        dialog.destroy()

    def on_main_window_destroy(self, window):
        if self.is_monitoring:
            self.stop_monitoring()
        Gtk.main_quit()

def main():
    app = NetworkMonitorGUI()
    app.window.show_all()
    Gtk.main()

if __name__ == "__main__":
    main()
