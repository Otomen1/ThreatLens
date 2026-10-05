import type { ReactNode } from "react";

export function ActionToolbar({ context, children, className = "" }: { context: ReactNode; children?: ReactNode; className?: string }) {
  return <div className={`ui-action-toolbar ${className}`}><div className="min-w-0 flex-1">{context}</div><div className="ui-toolbar-actions">{children}</div></div>;
}
