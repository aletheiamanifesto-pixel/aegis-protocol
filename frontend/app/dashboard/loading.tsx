export default function DashboardLoading() {
  return <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">{[1,2,3,4].map((i) => <div key={i} className="h-24 animate-pulse rounded-lg bg-white" />)}</div>;
}
