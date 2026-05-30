// ============================================================================
// NORVIQ UI KIT — app.jsx  (root: shell + routing)
// ============================================================================
const PAGES = {
  dashboard: Dashboard,
  policies: PolicyCatalog,
  audit: AuditLog,
  agents: AgentMonitor,
  threats: ThreatModeling,
  settings: Settings
};

function App() {
  const [page, setPage] = useState(() => {
    const h = (window.location.hash || "").replace("#", "");
    return PAGES[h] ? h : "dashboard";
  });
  const [cluster, setCluster] = useState("production-aks");
  const [namespace, setNamespace] = useState("chatbot-prod");
  useEffect(() => { window.location.hash = page; }, [page]);
  const selectCluster = (c) => { setCluster(c); setNamespace((NS_BY_CLUSTER[c] || ["default"])[0]); };
  const Current = PAGES[page] || Dashboard;
  return (
    <div className="app">
      <Sidebar page={page} onNavigate={setPage} />
      <div className="main">
        <Header cluster={cluster} namespace={namespace} onSelectCluster={selectCluster} onSelectNamespace={setNamespace} />
        <main className="content">
          <Current key={page} namespace={namespace} />
        </main>
      </div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
