import json
import streamlit as st
import pandas as pd

RESULT_FILE = "detection_results.json"

st.set_page_config(
    page_title="UEBA SOC Dashboard",
    layout="wide"
)


def load_results():
    try:
        with open(
            RESULT_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            return json.load(file)
    except:
        return []


results = load_results()

st.title(" UEBA Insider Threat Detection")
st.caption("User and Entity Behavior Analytics - SOC Dashboard")

if not results:
    st.error("No detection results found. Run main.py first.")
    st.stop()

df = pd.DataFrame(results)

st.sidebar.header("Filters")

search = st.sidebar.text_input(
    "Search user",
    placeholder="Enter username..."
)

risk_filter = st.sidebar.selectbox(
    "Risk level",
    ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
)

departments = sorted(
    df["department"]
    .dropna()
    .astype(str)
    .unique()
)

department_filter = st.sidebar.selectbox(
    "Department",
    ["ALL"] + departments
)

filtered = df.copy()

if search:
    filtered = filtered[
        filtered["username"].str.contains(
            search,
            case=False,
            na=False
        )
    ]

if risk_filter != "ALL":
    filtered = filtered[
        filtered["risk_level"] == risk_filter
    ]

if department_filter != "ALL":
    filtered = filtered[
        filtered["department"] == department_filter
    ]

total_users = len(df)

suspicious_users = len(
    df[df["risk_score"] > 0]
)

high_users = len(
    df[df["risk_level"] == "HIGH"]
)

critical_users = len(
    df[df["risk_level"] == "CRITICAL"]
)

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Users",
    total_users
)

col2.metric(
    "Suspicious Users",
    suspicious_users
)

col3.metric(
    "High Risk",
    high_users
)

col4.metric(
    "Critical",
    critical_users
)

st.divider()

st.subheader(" Suspicious Users")

display_df = filtered[
    [
        "username",
        "full_name",
        "department",
        "role",
        "risk_score",
        "risk_level",
        "anomaly_count"
    ]
].copy()

display_df = display_df[
    display_df["risk_score"] > 0
]

display_df = display_df.sort_values(
    "risk_score",
    ascending=False
)

if display_df.empty:
    st.info("No users match the selected filters.")
else:
    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True
    )

st.divider()

st.subheader(" Investigate User")

available_users = filtered[
    filtered["risk_score"] > 0
]["username"].tolist()

if not available_users:
    st.info("No suspicious users available.")
    st.stop()

selected_user = st.selectbox(
    "Select a suspicious user",
    available_users
)

user_data = df[
    df["username"] == selected_user
].iloc[0]

col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("User")
    st.write(f"Username: {user_data['username']}")
    st.write(f"Name: {user_data['full_name']}")
    st.write(f"User ID: {user_data['user_id']}")

with col2:
    st.subheader("Organization")
    st.write(f"Department: {user_data['department']}")
    st.write(f"Role: {user_data['role']}")
    st.write(
        f"Privilege Level: {user_data['privilege_level']}"
    )

with col3:
    st.subheader("Risk")
    st.metric(
        "Risk Score",
        f"{user_data['risk_score']}/100"
    )

    level = user_data["risk_level"]

    if level == "CRITICAL":
        st.error(f" {level}")
    elif level == "HIGH":
        st.warning(f" {level}")
    elif level == "MEDIUM":
        st.info(f" {level}")
    else:
        st.success(f" {level}")

st.divider()

st.subheader(" Why Is This User Suspicious?")

reasons = user_data.get("reasons", [])

if not reasons:
    st.success("No suspicious behavior detected.")
else:
    for reason in reasons:
        st.warning(f" {reason}")

st.divider()

st.subheader("Investigation Summary")

col1, col2, col3 = st.columns(3)

col1.metric(
    "Risk Score",
    user_data["risk_score"]
)

col2.metric(
    "Risk Level",
    user_data["risk_level"]
)

col3.metric(
    "Anomalies",
    user_data["anomaly_count"]
)

st.divider()

st.subheader("Risk Distribution")

risk_counts = df["risk_level"].value_counts()

chart_data = pd.DataFrame({
    "Users": risk_counts
})

st.bar_chart(chart_data)

st.caption("UEBA Insider Threat Detection System")
