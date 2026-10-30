import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage titleKey="res.organizations" descKey="res.organizationsDesc" path="v1/organizations" scoped={false}/>;
}
