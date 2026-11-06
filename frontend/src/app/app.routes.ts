import { Routes } from '@angular/router';
import { authGuard } from './core/auth';
import { HostsPage } from './pages/hosts-page';
import { ProjectsPage } from './pages/projects-page';
import { TeamPage } from './pages/team-page';
import { TriageDashboard } from './pages/triage-dashboard';

export const routes: Routes = [
  { path: '', component: TriageDashboard, canActivate: [authGuard] },
  { path: 'projects', component: ProjectsPage, canActivate: [authGuard] },
  { path: 'hosts', component: HostsPage, canActivate: [authGuard] },
  { path: 'team', component: TeamPage, canActivate: [authGuard] },
];
