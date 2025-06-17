# app.py

import streamlit as st
import time
import socket
import traceback
import ipaddress
from datetime import datetime
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from network_utils import NetworkDiagnostics

# ── 1) Page config ─────────────────────────────────────────────────────────────
st.set_page_config(page_title="Network Diagnostic Tool", page_icon="🌐", layout="wide")

# ── 2) Session‐state defaults ─────────────────────────────────────────────────
for key, default in {
    "ping_data":         [],
    "traceroute_data":   [],
    "monitoring_active": False,
    "target_host":       "",
    "error_logs":        [],
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

# ── 3) Helpers ─────────────────────────────────────────────────────────────────
def log_error(exc: Exception):
    tb = traceback.format_exc().strip().splitlines()[-1]
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.error_logs.append(f"[{timestamp}] {tb}")

def add_ping_data(latency: float, packet_loss: float):
    st.session_state.ping_data.append({
        "timestamp":   datetime.now(),
        "host":        st.session_state.target_host,
        "latency":     latency,
        "packet_loss": packet_loss,
    })
    if len(st.session_state.ping_data) > 100:
        st.session_state.ping_data = st.session_state.ping_data[-100:]

def do_single_ping():
    try:
        diag = NetworkDiagnostics()
        res  = diag.single_ping(st.session_state.target_host)
        if res["success"]:
            add_ping_data(res["latency"], res["packet_loss"])
        else:
            add_ping_data(0.0, 100.0)
            log_error(Exception(res.get("error", "Ping failed")))
    except Exception as e:
        log_error(e)

def resolve_dns(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        log_error(e)
        return "Resolution failed"

def scan_ports(host: str, ports: list[int]) -> dict[int, bool]:
    results = {}
    for port in ports:
        try:
            with socket.socket() as s:
                s.settimeout(0.5)
                results[port] = (s.connect_ex((host, port)) == 0)
        except Exception as e:
            results[port] = False
            log_error(e)
    return results

# ── 4) Main App ─────────────────────────────────────────────────────────────────
def main():
    st.title("🌐 Network Diagnostic Tool")
    st.markdown("Monitor latency, packet loss, DNS, port-scan, network-wide scan, and traceroute in real time.")

    # — Sidebar ──────────────────────────────────────────────────────────────────
    with st.sidebar:
        st.header("Configuration")
        host = st.text_input("Target IP/Hostname", value=st.session_state.target_host or "8.8.8.8")
        if host != st.session_state.target_host:
            st.session_state.target_host     = host
            st.session_state.ping_data.clear()
            st.session_state.traceroute_data.clear()
            st.session_state.error_logs.clear()

        interval = st.slider("Polling Interval (s)", 1, 10, 2)

        st.divider()
        st.header("Controls")
        if st.button("▶️ Start Monitoring", disabled=not host):
            st.session_state.monitoring_active = True
            st.rerun()
        if st.button("⏹️ Stop Monitoring"):
            st.session_state.monitoring_active = False
            st.rerun()
        if st.button("🗑️ Clear Data"):
            st.session_state.ping_data.clear()
            st.session_state.traceroute_data.clear()
            st.session_state.error_logs.clear()

        st.markdown("**Status:** " + ("🟢 Active" if st.session_state.monitoring_active else "🔴 Inactive"))

        # DNS Lookup
        if host:
            st.divider()
            st.subheader("🔍 DNS Lookup")
            ip = resolve_dns(host)
            st.write(f"Resolved IP: `{ip}`")

        # Port Scan (including 10443)
        if host:
            st.divider()
            st.subheader("🔌 Port Scan")
            default_ports = [22, 80, 443, 8080, 10443]
            ports = st.multiselect("Select Ports to Scan", default_ports, default=default_ports)
            if st.button("Start Port Scan"):
                results = scan_ports(host, ports)
                df = pd.DataFrame.from_dict(results, orient="index", columns=["Open"])
                st.dataframe(df.rename_axis("Port"), use_container_width=True)

        # Network-wide Scan
        st.divider()
        st.subheader("🌐 Network-wide Scan")
        net_cidr = st.text_input("Network CIDR", "192.168.1.0/24")
        if st.button("Scan Entire Network"):
            diag = NetworkDiagnostics()
            hosts = list(ipaddress.ip_network(net_cidr, strict=False).hosts())
            scan_ports_list = [22, 80, 443, 8080, 10443]
            results = []
            progress = st.progress(0)
            for i, ip in enumerate(hosts):
                ip_str = str(ip)
                ping_res = diag.single_ping(ip_str)
                port_res = scan_ports(ip_str, scan_ports_list) if ping_res["success"] else {p: False for p in scan_ports_list}
                results.append({"host": ip_str,
                                "reachable": ping_res["success"],
                                **{f"port_{p}": port_res[p] for p in scan_ports_list}})
                progress.progress((i + 1) / len(hosts))
            df_net = pd.DataFrame(results)
            st.dataframe(df_net, use_container_width=True)

    # — Real-time Metrics ─────────────────────────────────────────────────────────
    if st.session_state.ping_data:
        latest = st.session_state.ping_data[-1]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Latency",     f"{latest['latency']:.1f} ms")
        c2.metric("Packet Loss", f"{latest['packet_loss']:.1f} %")
        valid = [d["latency"] for d in st.session_state.ping_data if d["latency"] > 0]
        c3.metric("Avg Latency", f"{(sum(valid)/len(valid)):.1f} ms" if valid else "N/A")
        loss_avg = sum(d["packet_loss"] for d in st.session_state.ping_data) / len(st.session_state.ping_data)
        c4.metric("Total Loss",  f"{loss_avg:.1f} %")

    # — Charts & Raw History ───────────────────────────────────────────────────────
    if st.session_state.ping_data:
        df = pd.DataFrame(st.session_state.ping_data)
        st.subheader("📈 Latency Over Time")
        valid_df = df[df.latency > 0]
        fig1 = go.Figure()
        if not valid_df.empty:
            fig1.add_trace(go.Scatter(x=valid_df.timestamp, y=valid_df.latency, mode="lines+markers"))
        fig1.update_layout(xaxis_title="Time", yaxis_title="Latency (ms)", height=300)
        st.plotly_chart(fig1, use_container_width=True)

        st.subheader("📈 Packet Loss Over Time")
        fig2 = go.Figure(go.Scatter(x=df.timestamp, y=df.packet_loss, mode="lines+markers", fill="tonexty"))
        fig2.update_layout(xaxis_title="Time", yaxis_title="Packet Loss (%)", height=300)
        st.plotly_chart(fig2, use_container_width=True)

        if not valid_df.empty:
            st.subheader("📊 Latency Distribution")
            fig3 = px.histogram(valid_df, x="latency", nbins=20, labels={"latency":"Latency (ms)"})
            fig3.update_layout(height=300)
            st.plotly_chart(fig3, use_container_width=True)

        with st.expander("View Raw Ping History"):
            raw = df.copy()
            raw["Time"] = raw.timestamp.dt.strftime("%H:%M:%S")
            raw["Latency (ms)"] = raw.latency.apply(lambda x: f"{x:.1f}" if x>0 else "Timeout")
            raw["Packet Loss (%)"] = raw.packet_loss.apply(lambda x: f"{x:.1f}")
            st.dataframe(raw[["Time","host","Latency (ms)","Packet Loss (%)"]], hide_index=True)

    # — Traceroute ─────────────────────────────────────────────────────────────────
    st.header("🛤️ Network Path Analysis")
    colA, colB = st.columns([1,3])
    with colA:
        if st.button("🔍 Run Traceroute"):
            with st.spinner("Tracing…"):
                try:
                    diag = NetworkDiagnostics()
                    res  = diag.traceroute(st.session_state.target_host)
                    if res["success"]:
                        st.session_state.traceroute_data = res["hops"]
                    else:
                        log_error(Exception(res.get("error","Traceroute failed")))
                except Exception as e:
                    log_error(e)
                st.rerun()
    with colB:
        if st.session_state.traceroute_data:
            hops = pd.DataFrame(st.session_state.traceroute_data)
            fig  = go.Figure(go.Scatter(x=hops.hop, y=hops.latency, mode="lines+markers+text",
                                        text=hops.ip, textposition="top center"))
            fig.update_layout(xaxis_title="Hop", yaxis_title="Latency (ms)", height=300)
            st.plotly_chart(fig, use_container_width=True)
            hops["Status"] = hops.latency.apply(lambda x: "✅" if x>0 else "❌")
            hops["Latency (ms)"] = hops.latency.apply(lambda x: f"{x:.1f}" if x>0 else "Timeout")
            st.dataframe(hops[["hop","ip","Latency (ms)","Status"]], hide_index=True)

    # — Error Logs ─────────────────────────────────────────────────────────────────
    if st.session_state.error_logs:
        with st.expander("⚠️ Error Logs"):
            for line in st.session_state.error_logs:
                st.write(line)

    # ── 5) Ping Loop ───────────────────────────────────────────────────────────────
    if st.session_state.monitoring_active and st.session_state.target_host:
        do_single_ping()
        time.sleep(interval)
        st.rerun()

if __name__ == "__main__":
    main()
