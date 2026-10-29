import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage title="Organizations" path="v1/organizations" scoped={false}
    description="Your organization as seen by the control API."/>;
}
