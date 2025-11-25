/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { DeliveryModel } from '../models/delivery'
import * as security from '../lib/insecurity'

export function getDeliveryMethods () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const methods = await DeliveryModel.findAll()
    if (methods) {
      const sendMethods = []
      for (const method of methods) {
        sendMethods.push({
          id: method.id,
          name: method.name,
          price: security.isDeluxe(req) ? method.deluxePrice : method.price,
          eta: method.eta,
          icon: method.icon
        })
      }
      res.status(200).json({ status: 'success', data: sendMethods })
    } else {
      res.status(400).json({ status: 'error' })
    }
  }
}

export function getDeliveryMethod () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const userId = req.user?.id; // Assuming req.user is populated with authenticated user info
    if (!userId) {
      return res.status(401).json({ status: 'error', message: 'Unauthorized' });
    }

    const method = await DeliveryModel.findOne({ where: { id: req.params.id } })
    if (method != null) {
      // Add authorization check here
      if (!await isUserAuthorizedForDeliveryMethod(userId, method.id)) {
        return res.status(403).json({ status: 'error', message: 'Forbidden' });
      }

      const sendMethod = {
        id: method.id,
        name: method.name,
        price: security.isDeluxe(req) ? method.deluxePrice : method.price,
        eta: method.eta,
        icon: method.icon
      }
      res.status(200).json({ status: 'success', data: sendMethod })
    } else {
      res.status(404).json({ status: 'error', message: 'Not Found' })
    }
  }
}

async function isUserAuthorizedForDeliveryMethod(userId: number, deliveryMethodId: number): Promise<boolean> {
  // Implement your authorization logic here
  // For example, check if the user has access to the delivery method
  return true; // Placeholder implementation
}