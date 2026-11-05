import { Routes } from '@angular/router';
import { authGuard } from './core/auth';
import { HostsPage } from './pages/hosts-page';
import { ProjectsPage } from './pages/projects-page';
import { ServicesPage } from './pages/services-page';
import { TriageDashboard } from './pages/triage-dashboard';

export const routes: Routes = [
  { path: '', component: TriageDashboard, canActivate: [authGuard] },
  { path: 'projects', component: ProjectsPage, canActivate: [authGuard] },
  { path: 'hosts', component: HostsPage, canActivate: [authGuard] },
  // v1 service view, removed together with the v1 backend (Task 31)
  { path: 'services', component: ServicesPage, canActivate: [authGuard] },
];
