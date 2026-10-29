import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage titleKey="res.reports" descKey="res.reportsDesc" path="v1/reports" scoped={true}/>;
}
