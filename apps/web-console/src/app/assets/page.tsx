import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage title="Assets" path="v1/assets" scoped={true}
    description="Agents, models, MCP servers and tools registered in this workspace."/>;
}
