import { Routes } from '@angular/router';
import { HostsPage } from './pages/hosts-page';
import { RolloutsPage } from './pages/rollouts-page';
import { ServicesPage } from './pages/services-page';

export const routes: Routes = [
  { path: '', component: ServicesPage },
  { path: 'hosts', component: HostsPage },
  { path: 'rollouts', component: RolloutsPage },
];
