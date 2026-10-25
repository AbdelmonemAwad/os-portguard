<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\PortGuard;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm('general');
        $this->view->deviceForm = $this->getForm('dialogDevice');
        $this->view->formGridDevice = $this->getFormGrid('dialogDevice');
        $this->view->pick('OPNsense/PortGuard/index');
    }
}
