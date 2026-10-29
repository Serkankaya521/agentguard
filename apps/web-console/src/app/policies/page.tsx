import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage title="Policies" path="v1/policies" scoped={true}
    description="Signed, versioned runtime policies. Decisions are made in the runtime gateway, not here."/>;
}
