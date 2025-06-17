
import streamlit as st
import threading
import time
from datetime import datetime
from network_utils import NetworkDiagnostics

st.set_page_config(
    page_title="Network Diagnostic Tool",
    page_icon="🌐",
    layout="wide"
)

if 'ping_data' not in st.session_state:
    st.session_state.ping_data = []

if 'monitoring_active' not in st.session_state:
    st.session_state.monitoring_active = False

if 'target_host' not in st.session_state:
    st.session_state.target_host = ""

def add_ping_data(host, latency, packet_loss, timestamp):
    print("Adding ping data:", latency, packet_loss)
    st.session_state.ping_data.append({
        'timestamp': timestamp,
        'host': host,
        'latency': latency,
        'packet_loss': packet_loss
        })

def monitoring_loop(host, interval=2):
    net_diag = NetworkDiagnostics()
    print("Monitoring loop started")
    while st.session_state.monitoring_active:
        try:
            result = net_diag.single_ping(host)
            print("Ping result:", result)
            if result['success']:
                add_ping_data(
                    host,
                    result['latency'],
                    result['packet_loss'],
                    datetime.now()
                    )
            else:
                st.warning(f"Ping failed: {result.get('error', 'Unknown error')}")
            time.sleep(interval)
        except Exception as e:
                st.error(f"Monitoring error: {str(e)}")
                break

def main():
    st.title("Network Diagnostic Tool")

st.session_state.target_host = st.text_input("Enter target IP or hostname", "8.8.8.8")

if st.button("▶️ Start Monitoring", disabled=not st.session_state.target_host):
     if not st.session_state.monitoring_active:
         st.session_state.monitoring_active = True
         thread = threading.Thread(
             target=monitoring_loop,
             args=(st.session_state.target_host,),
             daemon=True
             )
         thread.start()
         st.success("Monitoring started!")
         st.rerun()

if st.button("⏹ Stop Monitoring"):
     if st.session_state.monitoring_active:
         st.session_state.monitoring_active = False
         st.success("Monitoring stopped!")
         st.rerun()

st.write("Ping data:", st.session_state.ping_data)

if st.session_state.ping_data:
     latest_data = st.session_state.ping_data[-1]

     col1, col2, col3, col4 = st.columns(4)

     with col1:
         st.metric("Current Latency", f"{latest_data['latency']:.1f} ms")

     with col2:
         st.metric("Packet Loss", f"{latest_data['packet_loss']:.1f}%")

     with col3:
         avg_latency = sum(d['latency'] for d in st.session_state.ping_data if d['latency'] > 0) / len([d for d in st.session_state.ping_data if d['latency'] > 0])
         st.metric("Average Latency", f"{avg_latency:.1f} ms")

     with col4:
         total_loss = sum(d['packet_loss'] for d in st.session_state.ping_data) / len(st.session_state.ping_data)
         st.metric("Total Packet Loss", f"{total_loss:.1f}%")

if __name__ == "__main__":
    main()
