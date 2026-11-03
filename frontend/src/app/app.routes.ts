import { Routes } from '@angular/router';
import { ServicesPage } from './pages/services-page';
import { HostsPage } from './pages/hosts-page';

export const routes: Routes = [
  { path: '', component: ServicesPage },
  { path: 'hosts', component: HostsPage },
  { path: '**', redirectTo: '' },
];
