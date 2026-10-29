import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage titleKey="res.approvals" descKey="res.approvalsDesc" path="v1/approval-requests" scoped={true}/>;
}
