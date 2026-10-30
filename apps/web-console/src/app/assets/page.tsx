import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage titleKey="res.assets" descKey="res.assetsDesc" path="v1/assets" scoped={true}/>;
}
