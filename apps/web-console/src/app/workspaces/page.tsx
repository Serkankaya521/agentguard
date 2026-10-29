import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage titleKey="res.workspaces" descKey="res.workspacesDesc" path="v1/workspaces" scoped={false}/>;
}
