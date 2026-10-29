import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage title="Reports" path="v1/reports" scoped={true}
    description="Scheduled and on-demand report jobs. Run assessment reports are downloaded from each run."/>;
}
