import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage title="Approvals" path="v1/approval-requests" scoped={true}
    description="Requests for high-risk agent actions and their expiry, decisions and revocations."/>;
}
