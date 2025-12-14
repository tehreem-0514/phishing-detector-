# app.py
import streamlit as st
from prediction import predict_url

# -----------------------
# Page config
# -----------------------
st.set_page_config(
    page_title="Phishing URL Detector",
    layout="wide",
    page_icon="🛡"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');

/* ================= GLOBAL ================= */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    font-size: 18px;
    line-height: 1.45;
    color: #000000 !important;
}

/* ================= BACKGROUND ================= */
/* ================= PROFESSIONAL SOFT BLUE BACKGROUND ================= */
.stApp {
    background: linear-gradient(
        180deg,
        #d9eaf7 0%,
        #e6f0f8 50%,
        #edf5fb 100%
    ) !important;
}


/* ================= HEADINGS ================= */
.report-heading {
    font-size: 28px;
    font-weight: 800;
    margin: 8px 0;
}

.report-subheading {
    font-size: 22px;
    font-weight: 700;
    margin: 6px 0;
}

/* ================= LAYOUT CLEANUP ================= */
.block-container {
    padding-top: 2rem !important;
}

div[data-testid="stVerticalBlock"] > div {
    gap: 0.4rem;
}

div[data-testid="InputInstructions"],
div[data-testid="stContainer"] > div:empty {
    display: none !important;
}

/* ================= PERFECT INPUT + BUTTON ALIGNMENT ================= */

/* Input outer wrapper */
.stTextInput > div {
    display: flex;
    align-items: center;
}

/* Input field */
.stTextInput input {
    height: 48px !important;
    line-height: 48px !important;
    padding: 0 14px !important;
    border-radius: 10px !important;
    box-sizing: border-box !important;
    background-color: #ffffff !important;
    color: #000000 !important;
    border: 2px solid #d0d7de !important;
    font-size: 16px !important;
}

/* Input placeholder */
.stTextInput input::placeholder {
    color: #6b7280 !important;
}

/* Input focus */
.stTextInput input:focus {
    border-color: #2563eb !important;
    box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.15);
    outline: none !important;
}

/* Button — Very Light Blue */
.stButton button {
    height: 40px !important;
    line-height: 48px !important;
    padding: 0 22px !important;
    border-radius: 10px !important;
    box-sizing: border-box !important;
    background-color: #60a5fa !important;   /* Lighter blue */
    color: #ffffff !important;
    border: none !important;
    font-size: 16px !important;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: center;
    letter-spacing: 0.3px;
}



/* Button hover */
.stButton button:hover {
    background-color: #1e4fd8 !important;
}

/* Remove Streamlit spacing bug */
.stButton {
    margin-top: 0 !important;
}

/* ================= FORCE DARK BLACK TEXT ================= */

/* All headings */
h1, h2, h3, h4, h5, h6 {
    color: #000000 !important;
}

/* Paragraphs, spans, labels, strong text */
p, span, strong, li, label {
    color: #000000 !important;
}

/* Streamlit markdown text */
.stMarkdown, .stMarkdown p {
    color: #000000 !important;
}

/* Streamlit warnings/info text */
.stAlert, .stWarning, .stInfo {
    color: #000000 !important;
}

</style>
""", unsafe_allow_html=True)



# -----------------------
# Title
# -----------------------
st.markdown(
    "<h1 class='report-heading'>🚩 Phishing URL Detector</h1>",
    unsafe_allow_html=True
)

# -----------------------
# URL input + Button
# -----------------------
col_url, col_btn = st.columns([5, 1], gap="small")
with col_url:
    url_input = st.text_input(
        "",
        placeholder="https://example.com",
        label_visibility="collapsed"
    )

with col_btn:
    check_button = st.button("🔍 Check URL", use_container_width=True)

# -----------------------
# Session state
# -----------------------
if "result" not in st.session_state:
    st.session_state.result = None

# -----------------------
# Prediction
# -----------------------
if check_button:
    if not url_input.strip():
        st.warning("Please enter a URL!")
    else:
        with st.spinner("Analyzing URL..."):
            st.session_state.result = predict_url(url_input)

# -----------------------
# REPORT
# -----------------------
if st.session_state.result:
    result = st.session_state.result

    st.markdown(
        "<h2 class='report-heading'>📊 URL Security Report</h2>",
        unsafe_allow_html=True
    )

    st.markdown(
        f"<p><strong>🔗 Analyzed URL:</strong> {result['url']}</p>",
        unsafe_allow_html=True
    )

    label_class = "label-safe" if result["label"] == "SAFE" else "label-phishing"
    st.markdown(
        f"<p><strong>📌 Classification:</strong> "
        f"<span class='{label_class}'>{result['label']}</span></p>",
        unsafe_allow_html=True
    )

    # Alerts
    if result.get("alerts"):
        st.markdown(
            "<h3 class='report-heading'>⚠️ Security Alerts</h3>",
            unsafe_allow_html=True
        )
        for alert in result["alerts"]:
            st.markdown(f"<p>- {alert}</p>", unsafe_allow_html=True)

    # -----------------------
    # LLM REPORT
    # -----------------------
    if result.get("llm_report"):
        st.markdown(
            "<h3 class='report-heading'>📝 Analysis Details</h3>",
            unsafe_allow_html=True
        )

        llm_text = result["llm_report"]

        headings = [
            "Classification Summary",
            "Key Suspicious Features",
            "Recommendations"
        ]

        # Replace ONLY markdown headings
        for h in headings:
            llm_text = llm_text.replace(
                f"### {h}", f"<h3 class='report-subheading'>{h}</h3>"
            )
            llm_text = llm_text.replace(
                f"## {h}", f"<h3 class='report-subheading'>{h}</h3>"
            )

        st.markdown(
            f"<div style='color:#000000;'>{llm_text}</div>",
            unsafe_allow_html=True
        )
