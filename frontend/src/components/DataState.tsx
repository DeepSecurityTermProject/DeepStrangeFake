export function LoadingState({ title = "Loading" }: { title?: string }) {
  return <div className="data-state">{title}</div>;
}

export function ErrorState({ title }: { title: string }) {
  return <div className="data-state data-state-error">{title}</div>;
}
