import type { ReactNode } from "react";

export function PanelTransition({ children, transitionKey }: { children: ReactNode; transitionKey: string }) {
  return <div key={transitionKey} className="ui-panel-enter">{children}</div>;
}
