import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage titleKey="res.integrations" descKey="res.integrationsDesc" path="v1/integrations" scoped={false}/>;
}
