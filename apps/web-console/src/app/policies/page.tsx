import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage titleKey="res.policies" descKey="res.policiesDesc" path="v1/policies" scoped={true}/>;
}
