import React, { useState } from "react";
import axios from "axios";

// Dynamically select API base URL: local for development, Azure for production
const API_BASE =
  process.env.REACT_APP_API_BASE || "http://127.0.0.1:5001";
console.log("Using API base URL:", API_BASE);

function App() {
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [logs, setLogs] = useState([]);
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [isRegistering, setIsRegistering] = useState(false);
  const [username, setUsername] = useState(localStorage.getItem("username") || "");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");


  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    setToken("");
    setUsername("");
    setLogs([]);
  };

  const fetchLogs = async () => {
    if (!token) {
      setError("You must be logged in to fetch logs.");
      return;
    }
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    try {
      const res = await axios.get(`${API_BASE}/audit-log`, {
        params: { start, end, tz },
        headers: { Authorization: `Bearer ${token}` },
      });
      setLogs(res.data);
      setError("");
    } catch (err) {
      if (err.response && err.response.status === 401) {
        handleLogout();
        setError("Session expired, please log in again.");
      } else {
        setError("Failed to fetch logs.");
      }
    }
  };

  const exportCSV = async () => {
    if (!token) {
      setError("You must be logged in to export CSV.");
      return;
    }
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    try {
      const res = await axios.get(`${API_BASE}/audit-log/export`, {
        params: { start, end, tz },
        responseType: "blob",
        headers: { Authorization: `Bearer ${token}` },
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", "audit_log.csv");
      document.body.appendChild(link);
      link.click();
      setError("");
    } catch (err) {
      if (err.response && err.response.status === 401) {
        handleLogout();
        setError("Session expired, please log in again.");
      } else {
        setError("Failed to export CSV.");
      }
    }
  };

  const handleLogin = async () => {
    setError("");
    try {
      const res = await axios.post(`${API_BASE}/login`, {
        username,
        password,
      });
      const jwt = res.data.access_token;
      localStorage.setItem("token", jwt);
      // Save username returned from backend if available, else keep entered one
      const returnedUsername = res.data.username || username;
      localStorage.setItem("username", returnedUsername);
      setUsername(returnedUsername);
      setToken(jwt);
      setPassword("");
    } catch (err) {
      setError("Login failed. Please check your credentials.");
    }
  };

  const handleRegister = async () => {
    setError("");
    try {
      await axios.post(`${API_BASE}/register`, {
        username,
        password,
      });
      setIsRegistering(false);
      setError("Registration successful. Please log in.");
      setUsername("");
      setPassword("");
    } catch (err) {
      setError("Registration failed. Username may already be taken.");
    }
  };

  // Sort logs by created_at_summary descending before rendering
  const sortedLogs = [...logs].sort((a, b) => {
    if (a.created_at_summary > b.created_at_summary) return -1;
    if (a.created_at_summary < b.created_at_summary) return 1;
    return 0;
  });

  if (!token) {
    return (
      <div style={{ padding: 20, maxWidth: 400, margin: "auto" }}>
        <h1>{isRegistering ? "Register" : "Login"}</h1>
        {error && <div style={{ color: "red", marginBottom: 10 }}>{error}</div>}
        <div style={{ marginBottom: 10 }}>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            style={{ width: "100%", padding: 8, marginBottom: 10 }}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{ width: "100%", padding: 8 }}
          />
        </div>
        {isRegistering ? (
          <>
            <button onClick={handleRegister} style={{ width: "100%", padding: 10 }}>
              Register
            </button>
            <div style={{ marginTop: 10, textAlign: "center" }}>
              <button
                onClick={() => {
                  setIsRegistering(false);
                  setError("");
                }}
                style={{ background: "none", border: "none", color: "blue", cursor: "pointer" }}
              >
                Already have an account? Login
              </button>
            </div>
          </>
        ) : (
          <>
            <button onClick={handleLogin} style={{ width: "100%", padding: 10 }}>
              Login
            </button>
            <div style={{ marginTop: 10, textAlign: "center" }}>
              <button
                onClick={() => {
                  setIsRegistering(true);
                  setError("");
                }}
                style={{ background: "none", border: "none", color: "blue", cursor: "pointer" }}
              >
                Don't have an account? Register
              </button>
            </div>
          </>
        )}
      </div>
    );
  }

  return (
    <div style={{ padding: 20 }}>
      <h1>
        AI Call Center Audit Log{" "}
        <span style={{ fontSize: 14, color: "#666", marginLeft: 10 }}>
          Logged in as {username}
        </span>
      </h1>
      <div style={{ marginBottom: 10 }}>
        <input
          type="date"
          value={start}
          onChange={(e) => setStart(e.target.value)}
        />
        <input
          type="date"
          value={end}
          onChange={(e) => setEnd(e.target.value)}
          style={{ marginLeft: 10 }}
        />
      </div>
      <button onClick={fetchLogs}>Run Report</button>
      <button onClick={exportCSV} style={{ marginLeft: 10 }}>
        Export CSV
      </button>
      <button onClick={handleLogout} style={{ marginLeft: 10, backgroundColor: "#f44336", color: "white" }}>
        Logout
      </button>
      {error && <div style={{ color: "red", marginTop: 10 }}>{error}</div>}

      <div style={{ marginTop: 20, display: "flex", flexWrap: "wrap", gap: "20px" }}>
        {sortedLogs.map((row, i) => (
          <CardWithCollapsibleMessages key={i} row={row} />
        ))}
      </div>
    </div>
  );
}

export default App;
// CardWithCollapsibleMessages: Card UI with collapsible messages section
function CardWithCollapsibleMessages({ row }) {
  const [expanded, setExpanded] = useState(false);
  const [metadataExpanded, setMetadataExpanded] = useState(false);
  const [audioSrc, setAudioSrc] = useState("");
  const isLong = row.messages && row.messages.length > 200;

  // Render patient name: prefer row.patient_name, then row.patient_name_encoded, else blank
  const patientDisplayName =
    row.patient_name
      ? row.patient_name
      : row.patient_name_encoded
      ? row.patient_name_encoded
      : "";

  const renderStyledMessages = () => {
    if (!row.messages) return null;
    const messagesArray = row.messages.split(" | ");
    return messagesArray.map((msg, idx) => {
      let bubbleStyle = {
        display: "inline-block",
        padding: "10px 14px",
        borderRadius: 18,
        margin: "6px 0",
        maxWidth: "75%",
        wordBreak: "break-word",
        fontSize: 15,
        boxShadow: "0 1px 2px rgba(0,0,0,0.03)",
      };
      let containerStyle = {
        display: "flex",
        width: "100%",
      };
      let label = null;
      let text = msg;
      if (msg.startsWith("AI:")) {
        bubbleStyle = {
          ...bubbleStyle,
          background: "#e3f1ff",
          color: "#1666c1",
          borderTopLeftRadius: 8,
          borderTopRightRadius: 22,
          borderBottomLeftRadius: 8,
          borderBottomRightRadius: 22,
          alignSelf: "flex-start",
        };
        containerStyle = { ...containerStyle, justifyContent: "flex-start" };
        label = <strong>AI: </strong>;
        text = msg.slice(3).trim();
      } else if (msg.startsWith("Caller:")) {
        bubbleStyle = {
          ...bubbleStyle,
          background: "#e5ffe3",
          color: "#1e7a1e",
          borderTopLeftRadius: 22,
          borderTopRightRadius: 8,
          borderBottomLeftRadius: 22,
          borderBottomRightRadius: 8,
          alignSelf: "flex-end",
        };
        containerStyle = { ...containerStyle, justifyContent: "flex-end" };
        label = <strong>Caller: </strong>;
        text = msg.slice(7).trim();
      }
      return (
        <div key={idx} style={containerStyle}>
          <div style={bubbleStyle}>
            {label}
            {text}
          </div>
        </div>
      );
    });
  };

  const displayText = expanded || !isLong
    ? null
    : row.messages.slice(0, 200) + (isLong ? "..." : "");


  return (
    <div style={{ border: "1px solid #ccc", borderRadius: 8, padding: 16, width: 320, boxShadow: "2px 2px 6px rgba(0,0,0,0.1)", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
      <div>
        <h3 style={{ margin: "0 0 8px 0" }}>
          {row.created_at_summary}
        </h3>
        <h4 style={{ margin: "0 0 8px 0" }}>
          Caller Name: {row.caller_name}
        </h4>
        <h4 style={{ margin: "0 0 8px 0" }}>
          Patient Name: {patientDisplayName}
        </h4>
        <div style={{ marginBottom: 8 }}>
          <strong>Audit Details:</strong>
          {/* Removed Call Duration line as per instructions */}
          <div>Call Length: {row.call_length}</div>
          <div>Category: {row.category}</div>
          <div>Status Summary: {row.status_summary}</div>
          <div>Nurse Name: {row.nurse_name}</div>
          <div>Nurse Phone: {row.nurse_phone}</div>
          <div>Reason for Escalation: {row.reason_for_escalation}</div>
          <div>Caller Callback Number: {row.caller_callback_number}</div>
          <div>Call From: {row.call_from}</div>
        </div>
        <div style={{ marginBottom: 8 }}>
          <strong>Summary:</strong>
          <div>{row.summary}</div>
        </div>
        <strong>Conversation:</strong>
        <div style={{ whiteSpace: "pre-wrap", wordWrap: "break-word", overflowY: "auto", border: "1px solid #eee", padding: 8, borderRadius: 4, marginBottom: 8 }}>
          {expanded ? renderStyledMessages() : displayText}
        </div>
        {isLong && (
          <button
            style={{ fontSize: 12, padding: "2px 8px", marginBottom: 4 }}
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? "Show Less" : "Show More"}
          </button>
        )}
        <div>
          <button
            style={{ fontSize: 12, padding: "2px 8px", marginBottom: 8 }}
            onClick={() => setMetadataExpanded((v) => !v)}
          >
            {metadataExpanded ? "Hide Metadata" : "Show Metadata"}
          </button>
          {metadataExpanded && (
            <div style={{ border: "1px solid #ddd", padding: 8, borderRadius: 4, fontSize: 12, color: "#333", marginBottom: 8 }}>
              <div><strong>Call SID:</strong> {row.call_sid}</div>
              <div><strong>Created At Summary:</strong> {row.created_at_summary}</div>
              <div><strong>Updated At Summary:</strong> {row.updated_at_summary}</div>
              <div><strong>Status Handoff:</strong> {row.status_handoff}</div>
              <div><strong>Call Duration:</strong> {row.call_duration}</div>
              <div><strong>Message OTP:</strong> {row.message_otp}</div>
              <div><strong>Nurse ID:</strong> {row.nurse_id}</div>
              <div><strong>Is Agent Handoff:</strong> {row.is_agent_handoff ? "Yes" : "No"}</div>
            </div>
          )}
        </div>
      </div>
      <div style={{ marginTop: 12, fontSize: 12, color: "#555" }}>
        {row.recording_filename ? (
          <>
            <div><strong>Recording:</strong></div>
            <audio
              controls
              preload="none"
              style={{ width: "100%", marginTop: 4 }}
              src={audioSrc}
              onPlay={(e) => {
                if (!audioSrc) {
                  const newSrc = `${API_BASE}/recording/${row.recording_filename}?token=${localStorage.getItem("token")}`;
                  setAudioSrc(newSrc);
                  // small delay to ensure source attaches, then play again automatically
                  setTimeout(() => {
                    e.target.play().catch(() => {});
                  }, 500);
                }
              }}
            >
              Your browser does not support the audio element.
            </audio>
          </>
        ) : (
          <div>No Recording Available</div>
        )}
      </div>
    </div>
  );
}