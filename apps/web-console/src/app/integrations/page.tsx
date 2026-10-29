import {ResourcePage} from '@/components/resource-page';

export default function Page() {
  return <ResourcePage title="Integrations" path="v1/integrations" scoped={false}
    description="Outbound destinations such as SIEM and ticketing. Credentials are never returned to the browser."/>;
}
