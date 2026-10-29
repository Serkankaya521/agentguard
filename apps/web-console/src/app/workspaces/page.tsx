import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage title="Workspaces" path="v1/workspaces" scoped={false}
    description="Workspaces separate teams, agents and permissions."/>;
}
